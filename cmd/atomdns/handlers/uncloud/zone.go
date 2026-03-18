package uncloud

import (
	"crypto/rand"
	"strings"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/uncloud/model"
	"codeberg.org/miekg/dns/dnsutil"
)

func (u *Uncloud) Purge(dur time.Duration) error {
	cutoff := time.Now().Add(-dur)
	_, err := u.db.Exec("DELETE FROM rrs WHERE date < ?", cutoff.Format(time.RFC3339))
	return err
}

// Domain checks if the domain name is registered by checking if there is an TXT record for it.
func (u *Uncloud) Domain(name string) bool {
	ints := []int{}
	err := u.db.Select(&ints, "SELECT 1 FROM rrs WHERE name LIKE ? AND type = ?", name+".%", "TXT")
	if err != nil {
		return false
	}
	return len(ints) > 0 && ints[0] == 1
}

func (u *Uncloud) CreateDomain() (string, error) {
	slug := rand.Text()[:10]
	name := dnsutil.Join(slug, u.Name)

	_, err := u.db.Exec("INSERT INTO rrs VALUES (?, ?, ?, ?)", name, "TXT", "It's Alive", 0)
	return name, err
}

func (u *Uncloud) CreateRecord(owner, domain string, input model.RecordRequest) (model.RecordResponse, error) {
	fqdn := dnsutil.Join(input.Name, domain)
	for _, value := range input.Values {
		_, err := u.db.Exec("INSERT INTO rrs VALUES (?, ?, ?, ?)", fqdn, strings.ToUpper(input.Type), value)
		if err != nil {
			return model.RecordResponse{}, err
		}
	}

	return model.RecordResponse{RecordRequest: input, FQDN: fqdn}, nil
}
