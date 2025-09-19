package template

import (
	"context"
	"regexp"
	"sync"
	gotmpl "text/template"

	"codeberg.org/miekg/dns"
)

type Template struct {
	Path         string
	sync.RWMutex // protects Template
	Template     *gotmpl.Template
	Regexp       *regexp.Regexp
	Types        []uint16
}

func (t *Template) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	})
}
