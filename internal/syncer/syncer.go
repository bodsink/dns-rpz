package syncer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/bodsink/dns-rpz/internal/store"
)

// ZoneSyncer performs AXFR sync for a single RPZ zone from a master server.
type ZoneSyncer struct {
	db     *store.DB
	index  Indexer
	logger *slog.Logger
}

// Indexer allows the syncer to update the in-memory DNS lookup index.
type Indexer interface {
	Add(name, action string)
	Remove(name string)
	Replace(newSet map[string]string)
	ReplaceZone(zoneID int64, newSet map[string]string)
}

// NewZoneSyncer creates a new ZoneSyncer.
func NewZoneSyncer(db *store.DB, index Indexer, logger *slog.Logger) *ZoneSyncer {
	return &ZoneSyncer{db: db, index: index, logger: logger}
}

// SyncAll performs AXFR sync for all enabled slave zones.
func (s *ZoneSyncer) SyncAll(ctx context.Context) error {
	zones, err := s.db.ListZones(ctx)
	if err != nil {
		return fmt.Errorf("list zones: %w", err)
	}

	for _, z := range zones {
		if !z.Enabled || z.Mode != "slave" {
			continue
		}
		if err := s.SyncZone(ctx, &z); err != nil {
			s.logger.Error("axfr sync failed", "zone", z.Name, "err", err)
		}
	}
	return nil
}

// SyncZone performs a full AXFR transfer for a single zone.
func (s *ZoneSyncer) SyncZone(ctx context.Context, z *store.Zone) error {
	histID, err := s.db.InsertSyncHistory(ctx, z.ID)
	if err != nil {
		return err
	}

	added, removed, syncErr := s.doAXFR(ctx, z)

	status := "success"
	errMsg := ""
	if syncErr != nil {
		status = "failed"
		errMsg = syncErr.Error()
		s.logger.Error("axfr failed", "zone", z.Name, "err", syncErr)
	} else {
		s.logger.Info("axfr sync complete",
			"zone", z.Name,
			"added", added,
			"removed", removed,
		)
	}

	if err := s.db.FinishSyncHistory(ctx, histID, status, added, removed, errMsg); err != nil {
		s.logger.Warn("finish sync history failed", "err", err)
	}
	if syncErr == nil {
		s.db.UpdateZoneSerial(ctx, z.ID, time.Now().Unix(), status) //nolint:errcheck
	}

	return syncErr
}

// doAXFR executes the actual AXFR transfer and stores records to the DB.
// Tries the primary master first, then falls back to secondary if available.
// Returns number of records added and removed.
func (s *ZoneSyncer) doAXFR(ctx context.Context, z *store.Zone) (added, removed int, err error) {
	master := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIP), z.MasterPort)
	added, removed, err = s.doAXFRFromMaster(ctx, z, master)
	if err != nil && z.MasterIPSecondary != "" {
		s.logger.Warn("primary master failed, trying secondary",
			"zone", z.Name,
			"primary", z.MasterIP,
			"secondary", z.MasterIPSecondary,
			"err", err,
		)
		secondaryMaster := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIPSecondary), z.MasterPort)
		added, removed, err = s.doAXFRFromMaster(ctx, z, secondaryMaster)
	}
	return
}

// stripCIDR removes the CIDR prefix notation from a PostgreSQL INET value.
// PostgreSQL returns INET values as "1.2.3.4/32" — we need just "1.2.3.4".
func stripCIDR(ip string) string {
	if idx := strings.IndexByte(ip, '/'); idx != -1 {
		return ip[:idx]
	}
	return ip
}

// stripZoneSuffix removes the RPZ zone name suffix from a record name.
// e.g. "pornhub.com.trustpositifkominfo." with zone "trustpositifkominfo." → "pornhub.com."
func stripZoneSuffix(name, zoneFQDN string) string {
	suffix := "." + zoneFQDN
	if strings.HasSuffix(name, suffix) {
		return name[:len(name)-len(zoneFQDN)]
	}
	return name
}

// doAXFRFromMaster performs the actual AXFR from a specific master address.
func (s *ZoneSyncer) doAXFRFromMaster(ctx context.Context, z *store.Zone, master string) (added, removed int, err error) {

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(z.Name))

	// Apply TSIG if configured
	if z.TSIGKey != "" && z.TSIGSecret != "" {
		m.SetTsig(z.TSIGKey, dns.HmacSHA256, 300, time.Now().Unix())
		t.TsigSecret = map[string]string{z.TSIGKey: z.TSIGSecret}
	}

	ch, err := t.In(m, master)
	if err != nil {
		return 0, 0, fmt.Errorf("axfr connect to %s: %w", master, err)
	}

	// Collect all records from AXFR stream
	var records []store.Record
	newNames := make(map[string]string) // name → RPZ action (CNAME target)

	for env := range ch {
		if env.Error != nil {
			return 0, 0, fmt.Errorf("axfr receive error: %w", env.Error)
		}
		for _, rr := range env.RR {
			// Skip SOA records — they are zone metadata
			if rr.Header().Rrtype == dns.TypeSOA {
				continue
			}
			name := stripZoneSuffix(dns.CanonicalName(rr.Header().Name), dns.Fqdn(z.Name))
			rtype := dns.TypeToString[rr.Header().Rrtype]
			rdata := rdataString(rr)

			records = append(records, store.Record{
				ZoneID: z.ID,
				Name:   name,
				RType:  rtype,
				RData:  rdata,
				TTL:    int(rr.Header().Ttl),
			})
			// Store CNAME target as RPZ action; non-CNAME records get empty action (default applies)
			if rtype == "CNAME" {
				newNames[name] = rdata
			} else {
				newNames[name] = ""
			}

			// Flush to DB in batches of 10,000 to avoid large transactions
			if len(records) >= 10_000 {
				if err := s.db.BulkUpsertRecords(ctx, z.ID, records); err != nil {
					return added, 0, err
				}
				added += len(records)
				records = records[:0]
			}
		}
	}

	// Flush remaining
	if len(records) > 0 {
		if err := s.db.BulkUpsertRecords(ctx, z.ID, records); err != nil {
			return added, 0, err
		}
		added += len(records)
	}

	// Remove stale records
	nameSlice := make([]string, 0, len(newNames))
	for n := range newNames {
		nameSlice = append(nameSlice, n)
	}
	rowsDeleted, err := s.db.DeleteRecordsNotIn(ctx, z.ID, nameSlice)
	if err != nil {
		return added, 0, err
	}
	removed = int(rowsDeleted)

	// Atomically update in-memory index for this zone only.
	s.index.ReplaceZone(z.ID, newNames)

	return added, removed, nil
}

// rdataString extracts the RDATA portion of a DNS record as a string.
func rdataString(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.CNAME:
		return v.Target
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.TXT:
		if len(v.Txt) > 0 {
			return v.Txt[0]
		}
		return ""
	default:
		return "."
	}
}

// Scheduler runs SyncAll periodically based on the configured interval.
type Scheduler struct {
	syncer   *ZoneSyncer
	interval time.Duration
	resetCh  chan time.Duration
	logger   *slog.Logger
}

// NewScheduler creates a Scheduler that runs AXFR sync at the given interval (seconds).
func NewScheduler(syncer *ZoneSyncer, intervalSeconds int, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		syncer:   syncer,
		interval: time.Duration(intervalSeconds) * time.Second,
		resetCh:  make(chan time.Duration, 1),
		logger:   logger,
	}
}

// SetInterval updates the sync interval at runtime without restarting the service.
// The new interval takes effect after the current tick cycle completes.
func (sc *Scheduler) SetInterval(seconds int) {
	d := time.Duration(seconds) * time.Second
	// Non-blocking send: if a pending reset already exists, replace it.
	select {
	case sc.resetCh <- d:
	default:
		// Drain and replace with the latest value.
		<-sc.resetCh
		sc.resetCh <- d
	}
}

// Run starts the sync scheduler loop. Blocks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) {
	sc.logger.Info("sync scheduler started", "interval", sc.interval)

	// Run once immediately on startup
	if err := sc.syncer.SyncAll(ctx); err != nil {
		sc.logger.Error("initial sync failed", "err", err)
	}

	ticker := time.NewTicker(sc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sc.logger.Info("sync scheduler stopped")
			return
		case newInterval := <-sc.resetCh:
			ticker.Reset(newInterval)
			sc.interval = newInterval
			sc.logger.Info("sync interval updated", "interval", newInterval)
		case <-ticker.C:
			if err := sc.syncer.SyncAll(ctx); err != nil {
				sc.logger.Error("periodic sync failed", "err", err)
			}
		}
	}
}
