package template

import (
	"fmt"
	"path/filepath"
	"regexp"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (t *Template) Setup(co *dnsserver.Controller) (err error) {
	if co.Next() {
		if !co.NextArg() {
			return co.ArgErr()
		}
		t.Regexp, err = regexp.Compile(co.Val())
		if err != nil {
			return err
		}

		types := co.RemainingArgs()
		for _, ty := range types {
			if j, ok := dns.StringToType[ty]; !ok {
				return co.PropErr(fmt.Errorf("%q is not a type", ty))
			} else {
				t.Types = append(t.Types, j)
			}
		}

		if co.NextBlock(0) {
			t.Path = co.Val()
			if !filepath.IsAbs(t.Path) {
				t.Path = filepath.Join(co.Global.Root, t.Path)
			}
		}
		// test execute the template on startup as do the wacthing
	}
	if t.Path == "" {
		return fmt.Errorf("no template path")
	}
	return nil
}
