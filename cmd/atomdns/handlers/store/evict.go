package store

import (
	"fmt"
	"time"
)

// Evict walks the stores and creates a list of maximum 10 items to delete. After the walk host itmes are
// eviects.
func (s *Store) Evict() {
	candidates := make([]Node, 0, 10)

	now := time.Now()
	fn := func(n Node) bool {
		if n.Time.After(now) {
			candidates = append(candidates, n)
			if len(candidates) > 9 {
				return false
			}
		}
		return true
	}
	for i := range candidates {
		s.Delete(candidates[i].Name)
	}

	s.Tree.Scan(fn)
}

func (s *Store) Dump() {
	fn := func(n Node) bool {
		fmt.Printf("%s\n", n)
		return true
	}
	s.Tree.Scan(fn)
}
