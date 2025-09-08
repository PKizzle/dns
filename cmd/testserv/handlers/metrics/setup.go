package metrics

import (
	"fmt"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/cmd/testserv/internal/dnsserver"
)

func (m *Metrics) Setup(co dnsserver.Controller) error {
	m.N = 10
	if co.Next() {
		if !co.NextArg() {
			return nil
		}
		if co.Val() == "disable" || co.Val() == "enable" || co.Val() == "" {
			if co.Val() == "disable" {
				m.disable = true
			}
			return nil
		}

		if !strings.HasPrefix(co.Val(), "/") {
			return co.PropErr(fmt.Errorf("invalid value: %q", co.Val()))
		}
		n, err := strconv.Atoi(co.Val()[1:])
		if err != nil || n < 0 {
			return co.PropErr(fmt.Errorf("not a (positive) number: %q", co.Val()[1:]))
		}
		m.N = uint64(n)

		if !co.NextArg() {
			return nil
		}

		if co.Val() == "disable" || co.Val() == "enable" || co.Val() == "" {
			if co.Val() == "disable" {
				m.disable = true
			}
		}
	}
	return nil
}
