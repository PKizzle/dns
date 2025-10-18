package geoip

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/oschwald/geoip2-golang/v2"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Geoip
	}{
		{
			`geoip {
                   		city testdata/GeoIPCity.dat
	        	}`,
			&Geoip{Subnet: false, City: new(geoip2.Reader)},
		},
		{
			`geoip subnet {
                   		city testdata/GeoIPCity.dat	testdata/GeoIPCity.dat
	        	}`,
			&Geoip{Subnet: true, City: new(geoip2.Reader), City6: new(geoip2.Reader)},
		},
	}
	for i, tc := range testcases {
		geoip := new(Geoip)
		co := dnsserver.NewTestController(tc.input)
		err := geoip.Setup(co)
		if err != nil {
			t.Fatal(err)
		}
		if tc.exp.Subnet != geoip.Subnet {
			t.Errorf("test %d: expected %t, got %t", i, tc.exp.Subnet, geoip.Subnet)
		}
		if geoip.City == nil {
			t.Errorf("test %d, city, expected non-nil, got nil", i)
		}

		if tc.exp.City == nil && geoip.City != nil {
			t.Errorf("test %d, city, expected nil, got %v", i, tc.exp.City)
		}
		if tc.exp.City6 == nil && geoip.City6 != nil {
			t.Errorf("test %d, city, expected nil, got %v", i, tc.exp.City6)
		}
	}
}
