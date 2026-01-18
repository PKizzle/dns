package atom

import (
	"strings"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestMsgInvalidFuncRace(t *testing.T) {
	conf := `
{
       dns {
               addr [::]:0
               limits {
                       run 1
               }
       }
}
.:0 {
       whoami
}
`
	s, err := New("<test>", strings.NewReader(conf))
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	var wg sync.WaitGroup
	run := func(fn dns.InvalidMsgFunc) {
		if fn == nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				fn(nil, nil)
			}
		}()
	}

	for _, srv := range s.servers {
		run(srv.MsgInvalidFunc)
	}
	for _, srv := range s.tlsservers {
		run(srv.MsgInvalidFunc)
	}

	wg.Wait()
}
