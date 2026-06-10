// Package geoip provides optional, fully offline IP geolocation using local
// MaxMind GeoLite2 databases. It makes no external calls; when no database is
// configured it is a no-op.
package geoip

import (
	"net"
	"strconv"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// Result holds what we surface about an IP.
type Result struct {
	Country string // ISO country code, e.g. "FR"
	City    string
	ASN     string // e.g. "AS3215"
	Org     string // autonomous system organization
}

// Empty reports whether nothing was found.
func (r Result) Empty() bool {
	return r.Country == "" && r.City == "" && r.ASN == "" && r.Org == ""
}

// Lookup wraps the optional City and ASN readers.
type Lookup struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// New opens whichever databases are configured. Empty paths are skipped.
func New(cityPath, asnPath string) (*Lookup, error) {
	l := &Lookup{}
	if cityPath != "" {
		r, err := maxminddb.Open(cityPath)
		if err != nil {
			return nil, err
		}
		l.city = r
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			return nil, err
		}
		l.asn = r
	}
	return l, nil
}

// Enabled reports whether any database is loaded.
func (l *Lookup) Enabled() bool {
	return l != nil && (l.city != nil || l.asn != nil)
}

// Lookup resolves an IP (bare address). Unknown fields are left empty.
func (l *Lookup) Lookup(ipStr string) Result {
	var res Result
	if l == nil {
		return res
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return res
	}
	if l.city != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}
		if err := l.city.Lookup(ip, &rec); err == nil {
			res.Country = rec.Country.ISOCode
			res.City = rec.City.Names["en"]
		}
	}
	if l.asn != nil {
		var rec struct {
			Number uint   `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if err := l.asn.Lookup(ip, &rec); err == nil {
			if rec.Number > 0 {
				res.ASN = "AS" + strconv.FormatUint(uint64(rec.Number), 10)
			}
			res.Org = rec.Org
		}
	}
	return res
}

// Close releases the database handles.
func (l *Lookup) Close() {
	if l == nil {
		return
	}
	if l.city != nil {
		l.city.Close()
	}
	if l.asn != nil {
		l.asn.Close()
	}
}
