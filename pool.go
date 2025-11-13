package dns

import (
	"strings"
	"sync"
)

// Pooler is an interface that mimics a sync.Pool, but allows for different implementation.
type Pooler interface {
	// Get returns a (newly allocated) byte slice.
	Get() []byte
	// Put returns the byte slice. This uses cap to determine the size of the buffer.
	Put([]byte)
}

// Pool is the default pool used. The allocation size used is [server.UDPSize], if TCP allocations stay below
// this value too, it is also used for that, otherwise they escape and are garbage collected.
type Pool struct {
	size int
	pool sync.Pool
}

func (p *Pool) Get() []byte { return p.pool.Get().([]byte) }

func (p *Pool) Put(b []byte) {
	if cap(b) > p.size {
		return
	}
	p.pool.Put(b[:cap(b)])
}

// NewPool returns a new Pooler of size.
func NewPool(size int) *Pool {
	return &Pool{
		size: size,
		pool: sync.Pool{
			New: func() any { return make([]byte, size) },
		},
	}
}

// noopPool is a Pooler that just allocates and does not cache.
type noopPool struct {
	size int
}

func (n *noopPool) Get() []byte { return make([]byte, n.size) }
func (n *noopPool) Put([]byte)  {}

func newNoopPool(size int) *noopPool { return &noopPool{size: size} }

// builderPooler is a pool used by the String methods.
type builderPooler struct {
	sync.Pool
}

func (s *builderPooler) Get() strings.Builder   { return s.Pool.Get().(strings.Builder) }
func (s *builderPooler) Put(sb strings.Builder) { sb.Reset(); s.Pool.Put(sb) }
