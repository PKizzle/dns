package dnsutil

import (
	"bufio"
	"strings"

	"codeberg.org/miekg/dns"
)

type state int

const (
	stateNone state = iota
	stateQuestion
	statePseudo
	stateAnswer
	stateAuthority
	stateAdditional
)

// StringToMsg convert a string as created by [Msg.String] back to an dns message. If the parsing fails and
// error is returned.
// The ";; QUESTION: 1, PSEUDO: 0, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 0" line is skipped is
// encountered.
func StringToMsg(s string) (*dns.Msg, error) {
	m := new(dns.Msg)
	state := stateNone

	// We have an RR or
	// ;; stuff, stuff2: more,  (comma seperated)
	// ;; <NAME> SECTION:
	// It's line by line, so that simplifies things
	scanner := bufio.NewScanner(strings.NewReader(s))

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, ";; QUESTION:") {
			// this is the section count line, we don't need it
			continue
		}

		if strings.HasPrefix(line, ";; QUESTION SECTION:") {
			state = stateQuestion
			continue
		}
		if strings.HasPrefix(line, ";; PSEUDO SECTION:") {
			state = statePseudo
			continue
		}
		if strings.HasPrefix(line, ";; ANSWER SECTION:") {
			state = stateAnswer
			continue
		}
		if strings.HasPrefix(line, ";; AUTHORITY SECTION:") {
			state = stateAuthority
			continue
		}
		if strings.HasPrefix(line, ";; ADDITIONAL SECTION:") {
			state = stateAdditional
			continue
		}

		// only here when to parse an RR, header is done above
		rr, err := dns.New(line)
		println("RRR", line, "bfp")
		if err != nil {
			return nil, err
		}
		switch state {
		case stateQuestion:
			m.Question = append(m.Question, rr)
		case statePseudo:
			m.Pseudo = append(m.Pseudo, rr)
		case stateAnswer:
			m.Answer = append(m.Answer, rr)
		case stateAuthority:
			m.Ns = append(m.Ns, rr)
		case stateAdditional:
			m.Extra = append(m.Extra, rr)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

func stringToHeader(line string, m *dns.Msg) {
	// parse a ';; QUERY, rcode: NOERROR, id: 49123, flags: qr rd ra' like line
	// if we so EDNS0 stuff a opt RR is added
}
