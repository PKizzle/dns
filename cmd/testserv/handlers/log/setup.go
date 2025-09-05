package log

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/testserv/conffile"
)

func (l *Log) Setup(d conffile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		if len(args) == 0 {
			l.tmpl = Template(Default)
			return nil
		}
		l.tmpl = Template(strings.Join(args, " "))
		return nil
	}

	return nil
}
