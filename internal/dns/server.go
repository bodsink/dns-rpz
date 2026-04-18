package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

// AXFRRecord is a single DNS record for outbound AXFR serving.
// Names must NOT include the zone suffix (the handler appends it).
type AXFRRecord struct {
	Name, RType, RData string
	TTL                int
}

// AXFRProvider serves zone records for outbound AXFR transfers.
// Implement and pass to Handler.SetAXFRProvider to enable slave-pull support.
type AXFRProvider interface {
	ListZoneRecordsForAXFR(ctx context.Context, zoneName string) (serial int64, records []AXFRRecord, err error)
}

// QueryLogger receives DNS query events for statistics collection.
// Implementations must be non-blocking to avoid slowing down query handling.
type QueryLogger interface {
	LogQuery(clientIP, domain, qtype, result, upstream string, rttMs int64)
}

// Handler handles incoming DNS queries with RPZ enforcement.
type Handler struct {
	index           Indexer
	acl             ACLChecker
	defaultAction   atomic.Value   // stores string: "nxdomain" or "nodata"
	upstream        unsafe.Pointer // *Upstream, swapped atomically
	logger          *slog.Logger
	auditLog        atomic.Bool  // when true, log every query at INFO level for audit purposes
	queryLog        atomic.Value // stores QueryLogger; nil when disabled
	queriesReceived atomic.Int64 // total queries received since startup (resets on restart)
	axfrProvider    AXFRProvider // optional; nil = AXFR not supported
}

// Indexer is the interface for looking up RPZ entries.
// Implemented by the in-memory index.
type Indexer interface {
	Lookup(name string) (action string, ok bool)
}

// ACLChecker checks whether a client IP is allowed to use recursion.
type ACLChecker interface {
	IsAllowed(ip net.IP) bool
}

// NewHandler creates a new DNS query handler.
// auditLog enables per-query INFO logging for audit purposes, independent of LOG_LEVEL.
func NewHandler(index Indexer, acl ACLChecker, defaultAction string, upstream *Upstream, logger *slog.Logger, auditLog bool) *Handler {
	h := &Handler{
		index:  index,
		acl:    acl,
		logger: logger,
	}
	h.defaultAction.Store(defaultAction)
	atomic.StorePointer(&h.upstream, unsafe.Pointer(upstream))
	h.auditLog.Store(auditLog)
	return h
}

// SetUpstream atomically replaces the upstream pool. Safe to call at runtime.
func (h *Handler) SetUpstream(u *Upstream) {
	atomic.StorePointer(&h.upstream, unsafe.Pointer(u))
}

// getUpstream returns the current upstream pool.
func (h *Handler) getUpstream() *Upstream {
	return (*Upstream)(atomic.LoadPointer(&h.upstream))
}

// SetAuditLog toggles audit logging at runtime without restarting the service.
func (h *Handler) SetAuditLog(v bool) {
	h.auditLog.Store(v)
}

// AuditLog returns the current audit log setting.
func (h *Handler) AuditLog() bool {
	return h.auditLog.Load()
}

// SetAXFRProvider registers a provider for outbound AXFR zone transfers.
// When set, this node can serve AXFR to slave nodes in the trust network.
// Pass nil to disable AXFR serving.
func (h *Handler) SetAXFRProvider(p AXFRProvider) {
	h.axfrProvider = p
}

// SetQueryLogger sets the query logger used for statistics collection.
// Pass nil to disable query logging.
func (h *Handler) SetQueryLogger(ql QueryLogger) {
	h.queryLog.Store(&ql)
}

// logQuery calls the query logger if one is set.
// For blocked/refused queries pass upstream="" and rttMs=0.
func (h *Handler) logQuery(clientIP, domain, qtype, result, upstream string, rttMs int64) {
	v := h.queryLog.Load()
	if v == nil {
		return
	}
	if qlp, ok := v.(*QueryLogger); ok && qlp != nil {
		(*qlp).LogQuery(clientIP, domain, qtype, result, upstream, rttMs)
	}
}

// SetDefaultAction updates the RPZ default action at runtime. Safe to call concurrently.
func (h *Handler) SetDefaultAction(action string) {
	h.defaultAction.Store(action)
}

// DefaultAction returns the current RPZ default action.
func (h *Handler) DefaultAction() string {
	if v, ok := h.defaultAction.Load().(string); ok {
		return v
	}
	return "nxdomain"
}

// QueryCount returns the total number of DNS queries received since startup.
// This counter is incremented atomically for every query before any processing,
// giving an accurate received count independent of the query log buffer.
// Resets to zero on process restart.
func (h *Handler) QueryCount() int64 {
	return h.queriesReceived.Load()
}

// ServeDNS handles a single DNS query.
// Implements dns.Handler interface.
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true
	m.RecursionAvailable = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// Count every valid query regardless of ACL/RPZ outcome or log buffer state.
	h.queriesReceived.Add(1)

	// Extract client IP for ACL check
	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m) //nolint:errcheck
		return
	}
	ip := net.ParseIP(clientIP)

	q := r.Question[0]
	qname := dns.Fqdn(q.Name)

	h.logger.Debug("dns query",
		"client", clientIP,
		"name", qname,
		"type", dns.TypeToString[q.Qtype],
	)

	// AXFR/IXFR — handled separately (zone transfer, not a regular query).
	if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
		h.handleAXFR(w, r, qname)
		return
	}

	// ACL check — only allowed IPs may recurse
	if !h.acl.IsAllowed(ip) {
		h.logger.Warn("query refused: client not in acl", "client", clientIP)
		if h.auditLog.Load() {
			h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "refused")
		}
		h.logQuery(clientIP, qname, dns.TypeToString[q.Qtype], "refused", "", 0)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// RPZ check — exact match, then wildcard walk up labels
	action, matched := h.index.Lookup(qname)
	if !matched {
		action, matched = h.lookupWildcard(qname)
	}
	if matched {
		if h.auditLog.Load() {
			h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "blocked", "action", action)
		}
		h.logQuery(clientIP, qname, dns.TypeToString[q.Qtype], "blocked", "", 0)
		h.applyRPZAction(w, r, m, qname, action, clientIP)
		return
	}

	if h.auditLog.Load() {
		h.logger.Info("audit", "client", clientIP, "name", qname, "type", dns.TypeToString[q.Qtype], "result", "allowed")
	}
	// Pass-through: forward to upstream resolver, then log with upstream stats.
	h.forward(w, r, m, clientIP, qname, dns.TypeToString[q.Qtype])
}

// forward sends the query to the upstream pool and relays the response.
// It calls logQuery with the upstream server address and RTT.
func (h *Handler) forward(w dns.ResponseWriter, r, m *dns.Msg, clientIP, qname, qtype string) {
	res, err := h.getUpstream().ExchangeTracked(r)
	if err != nil {
		h.logger.Warn("upstream error", "err", err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m) //nolint:errcheck
		h.logQuery(clientIP, qname, qtype, "allowed", "", 0)
		return
	}
	res.Resp.Id = r.Id
	w.WriteMsg(res.Resp) //nolint:errcheck
	h.logQuery(clientIP, qname, qtype, "allowed", res.Server, res.RTT.Milliseconds())
}

// lookupWildcard walks up the labels looking for a wildcard entry.
// e.g. "sub.example.com." checks "*.sub.example.com.", "*.example.com.", "*.com."
func (h *Handler) lookupWildcard(qname string) (action string, ok bool) {
	for off, end := 0, false; !end; off, end = dns.NextLabel(qname, off) {
		parent := qname[off:]
		if parent == "." {
			break
		}
		if action, ok = h.index.Lookup("*." + parent); ok {
			return
		}
	}
	return "", false
}

// applyRPZAction sends the appropriate DNS response based on the RPZ CNAME action.
// ".."    → NXDOMAIN (blocked, domain does not exist)
// "*."   → NODATA  (NOERROR, no answer records)
// other  → CNAME redirect (walled garden)
// ""     → use defaultAction from config
func (h *Handler) applyRPZAction(w dns.ResponseWriter, r, m *dns.Msg, qname, action, clientIP string) {
	// Empty action means no CNAME in zone — fall back to configured default
	if action == "" {
		action = h.DefaultAction()
	}

	h.logger.Info("rpz block", "client", clientIP, "name", qname, "action", action)

	switch action {
	case "*.":
		// NODATA: name exists but no records of requested type
		m.SetRcode(r, dns.RcodeSuccess)
		m.Ns = []dns.RR{rpzSOA(qname)}
	case ".", "nxdomain":
		// NXDOMAIN: name does not exist
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{rpzSOA(qname)}
	default:
		// Walled garden: redirect via CNAME
		m.SetRcode(r, dns.RcodeSuccess)
		m.Answer = []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
			Target: dns.Fqdn(action),
		}}
	}
	w.WriteMsg(m) //nolint:errcheck
}

// rpzSOA returns a minimal SOA record for the authority section of RPZ NXDOMAIN responses.
func rpzSOA(name string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30},
		Ns:      "rpz.localhost.",
		Mbox:    "hostmaster.rpz.localhost.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  30,
	}
}

// handleAXFR serves an outbound AXFR (zone transfer) for a zone stored in this node.
// Only available when an AXFRProvider has been set via SetAXFRProvider.
// The response format follows RFC 5936: SOA → records → SOA.
func (h *Handler) handleAXFR(w dns.ResponseWriter, r *dns.Msg, zoneFQDN string) {
	if h.axfrProvider == nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	// Strip trailing dot for the DB lookup; zones are stored without trailing dot.
	zoneName := strings.TrimSuffix(zoneFQDN, ".")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	serial, recs, err := h.axfrProvider.ListZoneRecordsForAXFR(ctx, zoneName)
	if err != nil {
		h.logger.Warn("axfr: zone not found or DB error", "zone", zoneName, "err", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m) //nolint:errcheck
		return
	}

	h.logger.Info("axfr: serving zone transfer", "zone", zoneName, "records", len(recs))

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: zoneFQDN, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + zoneFQDN,
		Mbox:    "hostmaster." + zoneFQDN,
		Serial:  uint32(serial),
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  60,
	}

	// Build envelopes: first SOA, then batches of records, then trailing SOA.
	const batchSize = 500
	envelopes := []*dns.Envelope{{RR: []dns.RR{soa}}}

	batch := make([]dns.RR, 0, batchSize)
	for _, rec := range recs {
		rr, err := buildAXFRRecord(rec, zoneFQDN)
		if err != nil {
			h.logger.Debug("axfr: skip unparseable record", "name", rec.Name, "rtype", rec.RType, "err", err)
			continue
		}
		batch = append(batch, rr)
		if len(batch) >= batchSize {
			envelopes = append(envelopes, &dns.Envelope{RR: batch})
			batch = make([]dns.RR, 0, batchSize)
		}
	}
	if len(batch) > 0 {
		envelopes = append(envelopes, &dns.Envelope{RR: batch})
	}
	envelopes = append(envelopes, &dns.Envelope{RR: []dns.RR{soa}}) // trailing SOA

	ch := make(chan *dns.Envelope, len(envelopes))
	for _, env := range envelopes {
		ch <- env
	}
	close(ch)

	tr := new(dns.Transfer)
	if err := tr.Out(w, r, ch); err != nil {
		h.logger.Warn("axfr: transfer out failed", "zone", zoneName, "err", err)
	}
}

// buildAXFRRecord converts an AXFRRecord into a dns.RR for AXFR transmission.
// The zoneFQDN (e.g. "rpz.example.com.") is appended to the record name so
// that slaves receive fully qualified names in the AXFR stream.
func buildAXFRRecord(rec AXFRRecord, zoneFQDN string) (dns.RR, error) {
	// Records are stored without zone suffix: "pornhub.com."
	// AXFR requires full name: "pornhub.com.rpz.example.com."
	var fullName string
	if rec.Name == "" || rec.Name == "." {
		fullName = zoneFQDN
	} else {
		// rec.Name already has trailing dot: "pornhub.com."
		// zoneFQDN has trailing dot: "rpz.example.com."
		// Full name: "pornhub.com." + "rpz.example.com." = "pornhub.com.rpz.example.com."
		fullName = rec.Name + zoneFQDN
	}

	ttl := uint32(rec.TTL)
	if ttl == 0 {
		ttl = 300
	}

	switch strings.ToUpper(rec.RType) {
	case "CNAME":
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: fullName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: dns.Fqdn(rec.RData),
		}, nil
	case "A":
		ip := net.ParseIP(rec.RData).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IPv4 %q", rec.RData)
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: fullName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		}, nil
	case "AAAA":
		ip := net.ParseIP(rec.RData)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 %q", rec.RData)
		}
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: fullName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported rtype %q", rec.RType)
	}
}


type Server struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	logger    *slog.Logger
}

// NewServer creates UDP and TCP DNS servers bound to the given address.
func NewServer(addr string, handler dns.Handler, logger *slog.Logger) *Server {
	return &Server{
		udpServer: &dns.Server{
			Addr:    addr,
			Net:     "udp",
			Handler: handler,
		},
		tcpServer: &dns.Server{
			Addr:    addr,
			Net:     "tcp",
			Handler: handler,
		},
		logger: logger,
	}
}

// Start starts both UDP and TCP DNS listeners.
// Blocks until ctx is cancelled or a listener fails.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("dns server starting", "addr", s.udpServer.Addr, "proto", "udp")
		if err := s.udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("udp server: %w", err)
		}
	}()

	go func() {
		s.logger.Info("dns server starting", "addr", s.tcpServer.Addr, "proto", "tcp")
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("tcp server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.udpServer.Shutdown() //nolint:errcheck
		s.tcpServer.Shutdown() //nolint:errcheck
		return nil
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully stops both DNS listeners.
func (s *Server) Shutdown() {
	s.udpServer.Shutdown() //nolint:errcheck
	s.tcpServer.Shutdown() //nolint:errcheck
}
