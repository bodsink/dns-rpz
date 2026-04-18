package dns

import (
	"fmt"

	"github.com/miekg/dns"
)

// AuthRecord is a DNS record loaded from the database for building the
// authoritative index. Used for zone_type = 'domain' and 'reverse_ptr'.
type AuthRecord struct {
	Name  string // domain name, with or without trailing dot
	RType string // "A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SOA", etc.
	RData string // rdata in zone-file text format
	TTL   int
}

// authZone holds all parsed records for one authoritative zone.
type authZone struct {
	names map[string]map[uint16][]dns.RR // FQDN name → qtype → []RR
	soa   dns.RR                         // SOA for authority section
}

// AuthoritativeIndex is an immutable in-memory index for authoritative DNS
// zones (zone_type = 'domain' or 'reverse_ptr').
//
// Records are parsed into dns.RR at build time (BuildAuthoritativeIndex) so
// that every lookup is zero-parse. The entire index is replaced atomically on
// SIGHUP via Handler.SetAuthoritativeIndex — no mutex needed because this struct
// is read-only after construction.
type AuthoritativeIndex struct {
	zones map[string]*authZone // zone apex FQDN → authZone
}

// Lookup returns the authoritative answer for (qname, qtype).
//
//   - isAuth=true  → we are authoritative for this name; do NOT forward.
//   - nxdomain=true → the exact name does not exist (NXDOMAIN + SOA in Ns).
//   - len(answer)==0, isAuth, !nxdomain → NODATA (NOERROR + SOA in Ns).
//   - soa is always the zone SOA when isAuth=true.
func (ai *AuthoritativeIndex) Lookup(qname string, qtype uint16) (answer []dns.RR, isAuth bool, nxdomain bool, soa dns.RR) {
	z := ai.findZone(qname)
	if z == nil {
		return nil, false, false, nil
	}

	nameRecs, exists := z.names[qname]
	if !exists {
		return nil, true, true, z.soa
	}

	if qtype == dns.TypeANY {
		for _, rrs := range nameRecs {
			answer = append(answer, rrs...)
		}
		return answer, true, false, z.soa
	}

	return nameRecs[qtype], true, false, z.soa
}

// Len returns the number of authoritative zones currently loaded.
func (ai *AuthoritativeIndex) Len() int {
	return len(ai.zones)
}

// findZone returns the authZone for which qname is a subdomain (or the apex itself).
// Walks up the labels from left to right until a matching zone apex is found.
func (ai *AuthoritativeIndex) findZone(qname string) *authZone {
	for off, end := 0, false; !end; off, end = dns.NextLabel(qname, off) {
		if z, ok := ai.zones[qname[off:]]; ok {
			return z
		}
	}
	return nil
}

// BuildAuthoritativeIndex parses a map of zoneName → []AuthRecord into an
// AuthoritativeIndex. Records that cannot be parsed by dns.NewRR are silently
// skipped. This is designed to be called infrequently (startup + SIGHUP).
func BuildAuthoritativeIndex(zoneRecords map[string][]AuthRecord) *AuthoritativeIndex {
	zones := make(map[string]*authZone, len(zoneRecords))

	for zoneName, recs := range zoneRecords {
		apexFQDN := dns.Fqdn(zoneName)
		names := make(map[string]map[uint16][]dns.RR)
		var soaRR dns.RR

		for _, rec := range recs {
			nameFQDN := dns.Fqdn(rec.Name)
			// Construct a zone-file line that dns.NewRR can parse.
			rrText := fmt.Sprintf("%s %d IN %s %s", nameFQDN, rec.TTL, rec.RType, rec.RData)
			rr, err := dns.NewRR(rrText)
			if err != nil {
				continue // skip malformed records gracefully
			}
			if rr.Header().Rrtype == dns.TypeSOA && soaRR == nil {
				soaRR = rr
			}
			if names[nameFQDN] == nil {
				names[nameFQDN] = make(map[uint16][]dns.RR)
			}
			t := rr.Header().Rrtype
			names[nameFQDN][t] = append(names[nameFQDN][t], rr)
		}

		if soaRR == nil {
			soaRR = synthesizeZoneSOA(apexFQDN)
		}

		zones[apexFQDN] = &authZone{names: names, soa: soaRR}
	}

	return &AuthoritativeIndex{zones: zones}
}

// synthesizeZoneSOA creates a minimal SOA record for zones that have no
// explicit SOA stored in the database.
func synthesizeZoneSOA(apex string) dns.RR {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + apex,
		Mbox:    "hostmaster." + apex,
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  300,
	}
}
