// Package cache answers repeated DNS queries from memory and passes the rest
// on to another handler, usually a forwarder.
package cache

import (
	"container/list"
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	// Used when the matching Config field is zero.
	defaultMaxEntries = 10_000
	defaultMaxTTL     = 24 * time.Hour

	flagRD uint16 = 0x0100 // recursion desired: echoed from each query
)

// Handler is what the cache wraps. It has the same method as server.Handler,
// so a *forward.Forwarder fits it, and a *Cache can be given to the server.
type Handler interface {
	Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error)
}

// Config holds the settings for a Cache.
type Config struct {
	// MaxEntries bounds the number of cached answers. When it is reached,
	// the least recently used one is dropped. Zero means 10,000.
	MaxEntries int

	// MaxTTL caps how long any answer is kept, whatever its TTL says.
	// Zero means 24 hours.
	MaxTTL time.Duration
}

func (c Config) maxEntries() int {
	if c.MaxEntries <= 0 {
		return defaultMaxEntries
	}
	return c.MaxEntries
}

func (c Config) maxTTL() time.Duration {
	if c.MaxTTL <= 0 {
		return defaultMaxTTL
	}
	return c.MaxTTL
}

// key identifies a cached answer. Names are compared without regard to case.
type key struct {
	name  string
	qtype dnsmessage.Type
	class dnsmessage.Class
}

func keyOf(q dnsmessage.Question) key {
	return key{name: strings.ToLower(q.Name), qtype: q.Type, class: q.Class}
}

type entry struct {
	key     key
	reply   *dnsmessage.Message // never modified once stored
	stored  time.Time
	expires time.Time
}

// A Cache is a Handler that remembers answers for as long as their TTLs
// allow. It is safe for use by many goroutines at once.
type Cache struct {
	next Handler
	cfg  Config
	now  func() time.Time // replaced in tests

	mu      sync.Mutex
	entries map[key]*list.Element // each Value is an *entry
	lru     *list.List            // most recently used at the front
}

// New returns a Cache in front of next. It returns ErrNilHandler if next is
// nil.
func New(next Handler, cfg Config) (*Cache, error) {
	if next == nil {
		return nil, ErrNilHandler
	}
	return &Cache{
		next:    next,
		cfg:     cfg,
		now:     time.Now,
		entries: make(map[key]*list.Element),
		lru:     list.New(),
	}, nil
}

// Handle implements server.Handler. Queries that are not a standard query
// with exactly one question are passed on without caching.
func (c *Cache) Handle(ctx context.Context, query *dnsmessage.Message) (*dnsmessage.Message, error) {
	if len(query.Questions) != 1 || query.Header.Opcode() != dnsmessage.OpcodeQuery {
		return c.next.Handle(ctx, query)
	}
	k := keyOf(query.Questions[0])

	if reply, ok := c.get(k, c.now()); ok {
		return answerFor(query, reply), nil
	}

	reply, err := c.next.Handle(ctx, query)
	if err != nil {
		return nil, err
	}
	if ttl, ok := cacheTTL(reply, c.cfg.maxTTL()); ok {
		c.put(k, reply, c.now(), ttl)
	}
	return reply, nil
}

// Len returns the number of cached answers, expired ones included until they
// are looked up or evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// get returns a copy of the answer cached under k, with its TTLs counted
// down to now. An expired entry is removed and reported as missing.
func (c *Cache) get(k key, now time.Time) (*dnsmessage.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if !now.Before(e.expires) {
		c.removeLocked(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return withTTLsLeft(e, now), true
}

// put stores a copy of reply under k for ttl, evicting the least recently
// used entry if the cache is full.
func (c *Cache) put(k key, reply *dnsmessage.Message, now time.Time, ttl time.Duration) {
	// Copied before taking the lock, so the lock is held as briefly as possible.
	e := &entry{key: k, reply: reply.Clone(), stored: now, expires: now.Add(ttl)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[k]; ok {
		el.Value = e
		c.lru.MoveToFront(el)
		return
	}
	c.entries[k] = c.lru.PushFront(e)
	if c.lru.Len() > c.cfg.maxEntries() {
		c.removeLocked(c.lru.Back())
	}
}

// removeLocked deletes el from the list and the map. c.mu must be held.
func (c *Cache) removeLocked(el *list.Element) {
	c.lru.Remove(el)
	delete(c.entries, el.Value.(*entry).key)
}

// withTTLsLeft returns a copy of e's reply with every TTL lowered by the time
// spent in the cache, and none longer than the entry has left.
func withTTLsLeft(e *entry, now time.Time) *dnsmessage.Message {
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	remaining := uint32(e.expires.Sub(now) / time.Second)

	m := e.reply.Clone()
	for _, section := range [][]dnsmessage.ResourceRecord{m.Answers, m.Authorities, m.Additionals} {
		for i := range section {
			rr := &section[i]
			if rr.Type() == dnsmessage.TypeOPT {
				continue // its TTL field holds EDNS flags, not a TTL
			}
			rr.TTL = min(rr.TTL-min(rr.TTL, elapsed), remaining)
		}
	}
	return m
}

// answerFor turns a cached reply into the reply to query: the ID and RD flag
// come from the query, and so does the question, keeping its letter case.
// reply must be a copy the caller owns.
func answerFor(query, reply *dnsmessage.Message) *dnsmessage.Message {
	reply.Header.ID = query.Header.ID
	reply.Header.Flags = reply.Header.Flags&^flagRD | query.Header.Flags&flagRD
	reply.Questions = slices.Clone(query.Questions)
	return reply
}

// cacheTTL reports whether reply may be cached, and for how long:
//   - an answer: the lowest TTL among its answer records
//   - NXDOMAIN or no data: the SOA's TTL or its Minimum, whichever is lower
//     (RFC 2308); without an SOA it is not cached
//   - truncated replies, other rcodes and TTL 0: not cached
func cacheTTL(reply *dnsmessage.Message, maxTTL time.Duration) (time.Duration, bool) {
	if reply.Header.Truncated() {
		return 0, false
	}
	var ttl uint32
	switch rcode := reply.Header.RCode(); {
	case rcode == dnsmessage.RCodeSuccess && len(reply.Answers) > 0:
		ttl = reply.Answers[0].TTL
		for _, rr := range reply.Answers[1:] {
			ttl = min(ttl, rr.TTL)
		}
	case rcode == dnsmessage.RCodeSuccess || rcode == dnsmessage.RCodeNameError:
		var ok bool
		if ttl, ok = negativeTTL(reply.Authorities); !ok {
			return 0, false
		}
	default:
		return 0, false
	}
	if ttl == 0 {
		return 0, false
	}
	return min(time.Duration(ttl)*time.Second, maxTTL), true
}

// negativeTTL returns how long a negative answer may be cached, from the SOA
// in its authority section.
func negativeTTL(authorities []dnsmessage.ResourceRecord) (uint32, bool) {
	for _, rr := range authorities {
		if soa, ok := rr.Data.(dnsmessage.SOA); ok {
			return min(rr.TTL, soa.Minimum), true
		}
	}
	return 0, false
}
