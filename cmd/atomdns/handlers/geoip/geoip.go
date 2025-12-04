package geoip

import (
	"context"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/oschwald/geoip2-golang/v2"
)

// Geoip adds location data to the context.
type Geoip struct {
	City  *geoip2.Reader
	City6 *geoip2.Reader
	Asn   *geoip2.Reader
	Asn6  *geoip2.Reader
}

func (g *Geoip) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		ip, _ := netip.ParseAddr(dnsutil.RemoteIP(w))
		if x := dnsctx.Value(ctx, "ecs/address"); x != nil {
			if s, ok := x.(netip.Addr); ok {
				log().Debug("Using 'ecs/address'")
				ip = s
			}
		}

		var (
			city *geoip2.City
			asn  *geoip2.ASN
			err  error
		)
		switch ip.Is4() {
		case true:
			if g.City != nil {
				if city, err = g.City.City(ip); err != nil {
					log().Debug("Lookup failed", Err(err))
				}
			}
			if g.Asn != nil {
				if asn, err = g.Asn.ASN(ip); err != nil {
					log().Debug("Lookup failed", Err(err))
				}
			}

		case false:
			if g.City6 != nil {
				if city, err = g.City6.City(ip); err != nil {
					log().Debug("Lookup failed", Err(err))
				}
			}
			if g.Asn6 != nil {
				if asn, err = g.Asn6.ASN(ip); err != nil {
					log().Debug("Lookup failed", Err(err))
				}
			}
		}
		if city.HasData() {
			dnsctx.WithValue(ctx, g.Key()+"/city", city.City.Names.English)
			regions := make([]string, len(city.Subdivisions))
			for i, region := range city.Subdivisions {
				regions[i] = region.ISOCode
			}
			dnsctx.WithValue(ctx, g.Key()+"/city/region", regions)
			dnsctx.WithValue(ctx, g.Key()+"/country", city.Country.ISOCode)
			dnsctx.WithValue(ctx, g.Key()+"/country/eu", city.Country.IsInEuropeanUnion)
			dnsctx.WithValue(ctx, g.Key()+"/continent", city.Continent.Code)
			dnsctx.WithValue(ctx, g.Key()+"/timezone", city.Location.TimeZone)
			if city.Location.HasCoordinates() {
				dnsctx.WithValue(ctx, g.Key()+"/latitude", *city.Location.Latitude)
				dnsctx.WithValue(ctx, g.Key()+"/longitude", *city.Location.Longitude)
			}
		}
		if asn.HasData() {
			dnsctx.WithValue(ctx, g.Key()+"/asn", asn.AutonomousSystemNumber)
			dnsctx.WithValue(ctx, g.Key()+"/asn/organization", asn.AutonomousSystemOrganization)
		}
		next.ServeDNS(ctx, w, r)
	})
}
