package msgcache

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// Evict walks the msgcache and creates a list of maximum 10 items to delete. After the walk host itmes are
// eviects.
func (m *Msgcache) Evict() {
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
		m.Delete(candidates[i].Name)
	}

	m.Tree.Scan(fn)
}

func (m *Msgcache) Dump() {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(tw, "RCODE\tTYPE\tEXPIRE\tNAME")
	fn := func(n Node) bool {
		fmt.Fprintln(tw, n.Rcode, "\t", n.Type, "\t", n.Time.Format(time.UnixDate), "\t", n.Name)
		return true
	}
	m.Tree.Scan(fn)
}
