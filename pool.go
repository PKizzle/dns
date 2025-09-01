package dns

import "sync"

// Pooler is an interface that mimics a sync.Pool, but allows for different implementation.
type Pooler interface {
	// Get returns a (newly allocated) byte slice.
	Get() []byte
	// Put returns the byte slice.
	Put([]byte)
}

// Pool is the default pool used. The allocation size used is [server.UDPSize], if TCP allocation stay below
// this value too, it is also used for that.
type Pool struct {
	size int
	pool sync.Pool
}

func (p *Pool) Get() []byte { return p.pool.Get().([]byte) }

func (p *Pool) Put(b []byte) {
	if p == nil { // Msg not created by the server.
		return
	}
	if len(b) > p.size {
		return
	}
	p.pool.Put(b)
}

func newPool(size int) *Pool {
	return &Pool{
		size: size,
		pool: sync.Pool{
			New: func() any { return make([]byte, size) },
		},
	}
}
