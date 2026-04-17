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
	db           *store.DB
	index        Indexer
	logger       *slog.Logger
	postSyncHook func() // called after a successful zone sync (optional)
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

// SetPostSyncHook registers a function to be called after every successful zone sync.
// Intended for the HTTP-only service to signal the DNS service to reload its index.
func (s *ZoneSyncer) SetPostSyncHook(fn func()) {
	s.postSyncHook = fn
}

// SyncAll performs AXFR sync for all enabled slave zones.
// Returns true if at least one zone failed to sync.
func (s *ZoneSyncer) SyncAll(ctx context.Context) (hasFailure bool) {
	zones, err := s.db.ListZones(ctx)
	if err != nil {
		s.logger.Error("list zones failed", "err", err)
		return true
	}

	for _, z := range zones {
		if !z.Enabled || z.Mode != "slave" {
			continue
		}
		if err := s.SyncZone(ctx, &z); err != nil {
			s.logger.Error("axfr sync failed", "zone", z.Name, "err", err)
			hasFailure = true
		}
	}
	return
}

// SyncZone performs a full AXFR transfer for a single zone.
func (s *ZoneSyncer) SyncZone(ctx context.Context, z *store.Zone) error {
	histID, err := s.db.InsertSyncHistory(ctx, z.ID)
	if err != nil {
		return err
	}

	added, removed, newSerial, syncErr := s.doAXFR(ctx, z)

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
		// Store the actual SOA serial from AXFR so the next sync can skip
		// if the zone hasn't changed.
		s.db.UpdateZoneSerial(ctx, z.ID, newSerial, status) //nolint:errcheck
		if s.postSyncHook != nil {
			s.postSyncHook()
		}
	}

	return syncErr
}

// doAXFR executes the actual AXFR transfer and stores records to the DB.
// Tries the primary master first, then falls back to secondary if available.
// Returns number of records added, removed, the actual SOA serial, and any error.
func (s *ZoneSyncer) doAXFR(ctx context.Context, z *store.Zone) (added, removed int, serial int64, err error) {
	master := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIP), z.MasterPort)
	added, removed, serial, err = s.doAXFRFromMaster(ctx, z, master)
	if err != nil && z.MasterIPSecondary != "" {
		s.logger.Warn("primary master failed, trying secondary",
			"zone", z.Name,
			"primary", stripCIDR(z.MasterIP),
			"secondary", stripCIDR(z.MasterIPSecondary),
			"err", err,
		)
		secondaryMaster := fmt.Sprintf("%s:%d", stripCIDR(z.MasterIPSecondary), z.MasterPort)
		added, removed, serial, err = s.doAXFRFromMaster(ctx, z, secondaryMaster)
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

// querySOASerial sends a SOA query to master and returns the zone serial.
// Returns 0, false if the query fails or no SOA is found.
func querySOASerial(zoneName, master string) (uint32, bool) {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zoneName), dns.TypeSOA)
	r, _, err := c.Exchange(m, master)
	if err != nil {
		return 0, false
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

// doAXFRFromMaster performs the actual AXFR from a specific master address.
func (s *ZoneSyncer) doAXFRFromMaster(ctx context.Context, z *store.Zone, master string) (added, removed int, serial int64, err error) {
	// Check SOA serial — skip the expensive AXFR if the zone hasn't changed.
	// z.Serial == 0 means never synced; always proceed.
	if z.Serial > 0 {
		if masterSerial, ok := querySOASerial(z.Name, master); ok && int64(masterSerial) == z.Serial {
			s.logger.Debug("zone serial unchanged, skipping axfr", "zone", z.Name, "serial", masterSerial)
			return 0, 0, z.Serial, nil
		}
	}

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
		return 0, 0, 0, fmt.Errorf("axfr connect to %s: %w", master, err)
	}

	// Open a bulk upsert session (COPY to temp table, then single INSERT SELECT at Finish).
	session, sessionErr := s.db.NewBulkUpsertSession(ctx, z.ID)
	if sessionErr != nil {
		return 0, 0, 0, fmt.Errorf("start bulk upsert session: %w", sessionErr)
	}

	// Collect all records from AXFR stream
	var records []store.Record
	var axfrSerial uint32 // SOA serial captured from the AXFR stream

	for env := range ch {
		if env.Error != nil {
			session.Close()
			return added, 0, 0, fmt.Errorf("axfr receive error: %w", env.Error)
		}
		for _, rr := range env.RR {
			// Capture SOA serial; skip storing SOA as a record.
			if soa, ok := rr.(*dns.SOA); ok {
				if axfrSerial == 0 {
					axfrSerial = soa.Serial
				}
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

			// Flush to staging table in batches of 10,000 to keep memory bounded.
			if len(records) >= 10_000 {
				if err := session.AddBatch(ctx, records); err != nil {
					session.Close()
				return 0, 0, 0, err
			}
			records = records[:0]
		}
	}
}

	// Flush remaining records to staging table.
	if len(records) > 0 {
		if err := session.AddBatch(ctx, records); err != nil {
			session.Close()
			return 0, 0, 0, err
		}
	}

	// DELETE old records + INSERT fresh from staging — atomic, no ON CONFLICT.
	// Finish() also returns added+removed counts.
	added, removed, err = session.Finish(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	return added, removed, int64(axfrSerial), nil
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
	syncer        *ZoneSyncer
	interval      time.Duration
	retryInterval time.Duration
	resetCh       chan time.Duration
	logger        *slog.Logger
}

// defaultRetryInterval is the wait time before retrying zones that failed to sync.
const defaultRetryInterval = 5 * time.Minute

// NewScheduler creates a Scheduler that runs AXFR sync at the given interval (seconds).
func NewScheduler(syncer *ZoneSyncer, intervalSeconds int, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		syncer:        syncer,
		interval:      time.Duration(intervalSeconds) * time.Second,
		retryInterval: defaultRetryInterval,
		resetCh:       make(chan time.Duration, 1),
		logger:        logger,
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
// If any zone fails to sync, it retries every retryInterval (default 5 minutes)
// until all zones succeed, then resumes the normal interval.
func (sc *Scheduler) Run(ctx context.Context) {
	sc.logger.Info("sync scheduler started", "interval", sc.interval)

	// Run once immediately on startup
	if sc.syncer.SyncAll(ctx) {
		sc.logger.Warn("initial sync has failures, will retry", "in", sc.retryInterval)
	}

	ticker := time.NewTicker(sc.interval)
	defer ticker.Stop()

	// retryTimer is a nil channel (blocks forever) when there is nothing to retry.
	// It is set to a real timer when the previous SyncAll had at least one failure.
	var retryTimer <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			sc.logger.Info("sync scheduler stopped")
			return

		case newInterval := <-sc.resetCh:
			ticker.Reset(newInterval)
			sc.interval = newInterval
			sc.logger.Info("sync interval updated", "interval", newInterval)

		case <-retryTimer:
			sc.logger.Info("retrying failed zone syncs")
			if sc.syncer.SyncAll(ctx) {
				sc.logger.Warn("retry still has failures, will retry again", "in", sc.retryInterval)
				retryTimer = time.After(sc.retryInterval)
			} else {
				sc.logger.Info("all zones synced successfully after retry")
				retryTimer = nil
			}

		case <-ticker.C:
			// Normal interval tick — reset any pending retry.
			retryTimer = nil
			if sc.syncer.SyncAll(ctx) {
				sc.logger.Warn("periodic sync has failures, will retry", "in", sc.retryInterval)
				retryTimer = time.After(sc.retryInterval)
			}
		}
	}
}
