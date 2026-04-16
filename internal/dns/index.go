package dns

import (
	"net"
	"sync"

	"github.com/miekg/dns"
)

// Index is a thread-safe in-memory map of blocked domain names to their RPZ action.
// Action is the CNAME target from the RPZ zone (e.g. ".", "*.", "walled.garden.").
// Optimized for read-heavy workloads (millions of entries, frequent lookups).
type Index struct {
	mu      sync.RWMutex
	blocked map[string]string // name → action (CNAME target)
}

// NewIndex creates an empty Index with optional pre-allocated capacity.
func NewIndex(capacity int) *Index {
	return &Index{
		blocked: make(map[string]string, capacity),
	}
}

// Add inserts a domain name with its RPZ action into the index.
// The name is normalized to FQDN lowercase.
func (idx *Index) Add(name, action string) {
	key := dns.CanonicalName(name)
	idx.mu.Lock()
	idx.blocked[key] = action
	idx.mu.Unlock()
}

// Remove deletes a domain name from the index.
func (idx *Index) Remove(name string) {
	key := dns.CanonicalName(name)
	idx.mu.Lock()
	delete(idx.blocked, key)
	idx.mu.Unlock()
}

// Lookup returns the RPZ action for a domain name, if present.
func (idx *Index) Lookup(name string) (action string, ok bool) {
	key := dns.CanonicalName(name)
	idx.mu.RLock()
	action, ok = idx.blocked[key]
	idx.mu.RUnlock()
	return
}

// Replace atomically replaces the entire index with newSet.
// Keys are normalized to FQDN lowercase, same as Add().
// Used after a full AXFR sync to swap in new data without downtime.
func (idx *Index) Replace(newSet map[string]string) {
	normalized := make(map[string]string, len(newSet))
	for k, v := range newSet {
		normalized[dns.CanonicalName(k)] = v
	}
	idx.mu.Lock()
	idx.blocked = normalized
	idx.mu.Unlock()
}

// Len returns the current number of entries in the index.
func (idx *Index) Len() int {
	idx.mu.RLock()
	n := len(idx.blocked)
	idx.mu.RUnlock()
	return n
}

// ACL is a thread-safe in-memory list of allowed CIDR ranges for recursion.
type ACL struct {
	mu   sync.RWMutex
	nets []*net.IPNet
}

// NewACL creates an empty ACL.
func NewACL() *ACL {
	return &ACL{}
}

// Load replaces all CIDR entries in the ACL.
// cidrStrings must be valid CIDR notation, e.g. "192.168.1.0/24".
// Invalid entries are skipped and do not cause an error.
func (a *ACL) Load(cidrStrings []string) {
	nets := make([]*net.IPNet, 0, len(cidrStrings))
	for _, s := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	a.mu.Lock()
	a.nets = nets
	a.mu.Unlock()
}

// IsAllowed reports whether the given IP is covered by any ACL entry.
// If the ACL is empty, all IPs are denied.
func (a *ACL) IsAllowed(ip net.IP) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the number of CIDR entries in the ACL.
func (a *ACL) Len() int {
	a.mu.RLock()
	n := len(a.nets)
	a.mu.RUnlock()
	return n
}
