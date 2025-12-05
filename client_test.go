package dns_test

import (
	"context"
	"fmt"
	"log"

	"codeberg.org/miekg/dns"
)

func ExampleExchange() {
	m := dns.NewMsg("www.example.org", dns.TypeA)
	r, err := dns.Exchange(context.TODO(), m, "udp", "8.8.8.8:53")
	if err != nil {
		log.Printf("Failed to retrieve records: %v", err)
		return
	}
	for _, answer := range r.Answer {
		if a, ok := answer.(*dns.A); ok {
			fmt.Println(a.A)
		}
	}
}
