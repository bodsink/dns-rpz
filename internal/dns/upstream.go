package dns

import (
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// UpstreamStrategy defines how queries are distributed across upstream resolvers.
type UpstreamStrategy string

const (
	StrategyRoundRobin UpstreamStrategy = "roundrobin"
	StrategyRandom     UpstreamStrategy = "random"
	StrategyRace       UpstreamStrategy = "race"
)

// Upstream manages a pool of DNS resolvers with a configurable dispatch strategy.
type Upstream struct {
	servers   []string
	strategy  UpstreamStrategy
	counter   atomic.Uint64
	client    *dns.Client
	tcpClient *dns.Client // used for TC (truncated) retry
	cache     *ResponseCache // nil = caching disabled
}

// NewUpstream creates an Upstream pool from the given server list and strategy string.
// Falls back to roundrobin for unknown strategy values.
// cache may be nil to disable response caching.
func NewUpstream(servers []string, strategy string, cache *ResponseCache) *Upstream {
	s := UpstreamStrategy(strategy)
	switch s {
	case StrategyRoundRobin, StrategyRandom, StrategyRace:
	default:
		s = StrategyRoundRobin
	}
	return &Upstream{
		servers:  servers,
		strategy: s,
		cache:    cache,
		client: &dns.Client{
			Net:            "udp",
			Timeout:        5 * time.Second,
			UDPSize:        4096,
			SingleInflight: true, // deduplicate identical in-flight queries
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: 5 * time.Second,
		},
	}
}

// Exchange sends the query using the configured strategy and returns the response.
// If a cache is configured, the cache is consulted first and the response is
// stored on a successful upstream call.
func (u *Upstream) Exchange(r *dns.Msg) (*dns.Msg, error) {
	var qname string
	var qtype uint16
	if u.cache != nil && len(r.Question) > 0 {
		qname = r.Question[0].Name
		qtype = r.Question[0].Qtype
		if cached, ok := u.cache.Get(qname, qtype); ok {
			return cached, nil
		}
	}

	var (
		resp *dns.Msg
		err  error
	)
	switch u.strategy {
	case StrategyRandom:
		resp, err = u.exchangeRandom(r)
	case StrategyRace:
		resp, err = u.exchangeRace(r)
	default:
		resp, err = u.exchangeRoundRobin(r)
	}

	if u.cache != nil && err == nil && qname != "" {
		u.cache.Set(qname, qtype, resp)
	}
	return resp, err
}

// exchangeOne sends a single query to addr, retrying via TCP if the UDP response is truncated.
func (u *Upstream) exchangeOne(r *dns.Msg, addr string) (*dns.Msg, error) {
	resp, _, err := u.client.Exchange(r.Copy(), addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, _, err = u.tcpClient.Exchange(r.Copy(), addr)
	}
	return resp, err
}

// exchangeRoundRobin picks the next server in rotation using an atomic counter.
func (u *Upstream) exchangeRoundRobin(r *dns.Msg) (*dns.Msg, error) {
	n := len(u.servers)
	idx := int(u.counter.Add(1)-1) % n
	resp, err := u.exchangeOne(r, u.servers[idx])
	if err != nil && n > 1 {
		// Fallback: try the next one
		resp, err = u.exchangeOne(r, u.servers[(idx+1)%n])
	}
	return resp, err
}

// exchangeRandom picks a random server each time.
func (u *Upstream) exchangeRandom(r *dns.Msg) (*dns.Msg, error) {
	servers := make([]string, len(u.servers))
	copy(servers, u.servers)
	rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })

	var (
		resp *dns.Msg
		err  error
	)
	for _, s := range servers {
		resp, err = u.exchangeOne(r, s)
		if err == nil {
			return resp, nil
		}
	}
	return resp, err
}

// exchangeRace sends to all servers simultaneously and returns the first successful response.
func (u *Upstream) exchangeRace(r *dns.Msg) (*dns.Msg, error) {
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(u.servers))

	for _, s := range u.servers {
		go func(addr string) {
			resp, err := u.exchangeOne(r, addr)
			ch <- result{resp, err}
		}(s)
	}

	var lastErr error
	for range u.servers {
		res := <-ch
		if res.err == nil {
			return res.resp, nil
		}
		lastErr = res.err
	}
	return nil, lastErr
}
