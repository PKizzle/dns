package rdata

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"codeberg.org/miekg/dns/internal/dnsstring"
	"codeberg.org/miekg/dns/pool"
)

var builderPool = &pool.Builder{Pool: sync.Pool{New: func() any { return strings.Builder{} }}}

func (rr RRSIG) String() string {
	sb := builderPool.Get()
	sprintData(&sb, typeToString(rr.TypeCovered),
		strconv.Itoa(int(rr.Algorithm)),
		strconv.Itoa(int(rr.Labels)),
		strconv.FormatInt(int64(rr.OrigTTL), 10),
		dnsutilTimeToString(rr.Expiration),
		dnsutilTimeToString(rr.Inception),
		strconv.Itoa(int(rr.KeyTag)),
		rr.SignerName,
		rr.Signature)
	s := sb.String()
	builderPool.Put(sb)
	return s
}

func (rr LOC) String() string {
	sb := builderPool.Get()
	lat := rr.Latitude
	ns := "N"
	if lat > dnsstring.LOCEquator {
		lat = lat - dnsstring.LOCEquator
	} else {
		ns = "S"
		lat = dnsstring.LOCEquator - lat
	}
	h := lat / dnsstring.LOCDegrees
	lat = lat % dnsstring.LOCDegrees
	m := lat / dnsstring.LOCHours
	lat = lat % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lat)/1000, ns))

	lon := rr.Longitude
	ew := "E"
	if lon > dnsstring.LOCPrimemeridian {
		lon = lon - dnsstring.LOCPrimemeridian
	} else {
		ew = "W"
		lon = dnsstring.LOCPrimemeridian - lon
	}
	h = lon / dnsstring.LOCDegrees
	lon = lon % dnsstring.LOCDegrees
	m = lon / dnsstring.LOCHours
	lon = lon % dnsstring.LOCHours

	sb.WriteString(fmt.Sprintf("%02d %02d %0.3f %s ", h, m, float64(lon)/1000, ew))

	alt := float64(rr.Altitude) / 100
	alt -= dnsstring.LOCAltitudebase
	if rr.Altitude%100 != 0 {
		sb.WriteString(fmt.Sprintf("%.2fm ", alt))
	} else {
		sb.WriteString(fmt.Sprintf("%.0fm ", alt))
	}

	sb.WriteString(cmToM(rr.Size) + "m ")
	sb.WriteString(cmToM(rr.HorizPre) + "m ")
	sb.WriteString(cmToM(rr.VertPre) + "m")
	s := sb.String()
	builderPool.Put(sb)
	return s
}
