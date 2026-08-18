package ldap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// This file implements just enough of LDAPv3 (RFC 4511) to drive the real
// go-ldap client: simple bind, base-scoped search with an equality or presence
// filter, unbind, and the StartTLS extended operation. It exists so the
// Authenticator can be tested against actual protocol exchanges — including the
// details that matter to us, like which DN was bound, which filter was sent and
// which attributes were requested — without a real directory.

// LDAP protocol constants (application tags and result codes) used below.
const (
	appBindRequest        = 0
	appBindResponse       = 1
	appUnbindRequest      = 2
	appSearchRequest      = 3
	appSearchResultEntry  = 4
	appSearchResultDone   = 5
	appAbandonRequest     = 16
	appExtendedRequest    = 23
	appExtendedResponse   = 24
	resultSuccess         = 0
	resultProtocolError   = 2
	resultNoSuchObject    = 32
	resultInvalidCreds    = 49
	resultUnwillingToPerf = 53
	oidStartTLS           = "1.3.6.1.4.1.1466.20037"
)

// bindRec and searchRec record what the client actually sent, per connection.
type bindRec struct {
	conn     int
	dn       string
	password string
}

type searchRec struct {
	conn        int
	base        string
	filterAttr  string
	filterValue string
	present     bool // "(attr=*)" rather than an equality match
	attrs       []string
}

type fakeDir struct {
	t  *testing.T
	ln net.Listener

	// Fixtures.
	passwords map[string]string              // DN -> accepted password
	entries   map[string]map[string][]string // DN -> attribute -> values
	emptyFor  map[string]bool                // DNs answering success with no entry
	startTLS  bool                           // accept the StartTLS extended request
	cert      tls.Certificate

	mu       sync.Mutex
	conns    int
	binds    []bindRec
	searches []searchRec
}

// newFakeDir starts a directory on a loopback port and stops it with the test.
func newFakeDir(t *testing.T) *fakeDir {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDir{
		t:         t,
		ln:        ln,
		passwords: map[string]string{},
		entries:   map[string]map[string][]string{},
		emptyFor:  map[string]bool{},
	}
	go d.accept()
	t.Cleanup(func() { ln.Close() })
	return d
}

func (d *fakeDir) url() string { return "ldap://" + d.ln.Addr().String() }

func (d *fakeDir) accept() {
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return // listener closed by the test cleanup
		}
		d.mu.Lock()
		d.conns++
		id := d.conns
		d.mu.Unlock()
		go d.serve(c, id)
	}
}

// record helpers ------------------------------------------------------------

func (d *fakeDir) recordBind(r bindRec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.binds = append(d.binds, r)
}

func (d *fakeDir) recordSearch(r searchRec) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searches = append(d.searches, r)
}

func (d *fakeDir) bindLog() []bindRec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]bindRec(nil), d.binds...)
}

func (d *fakeDir) searchLog() []searchRec {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]searchRec(nil), d.searches...)
}

func (d *fakeDir) connCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}

// serve handles one connection until the client goes away.
func (d *fakeDir) serve(c net.Conn, id int) {
	defer c.Close()
	conn := c
	for {
		req, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(req.Children) < 2 {
			return
		}
		msgID, ok := req.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := req.Children[1]

		switch op.Tag {
		case appBindRequest:
			d.handleBind(conn, id, msgID, op)
		case appSearchRequest:
			d.handleSearch(conn, id, msgID, op)
		case appUnbindRequest:
			return
		case appAbandonRequest:
			// No response is defined for abandon.
		case appExtendedRequest:
			tlsConn, err := d.handleExtended(conn, msgID, op)
			if err != nil {
				return
			}
			if tlsConn != nil {
				conn = tlsConn
			}
		default:
			d.write(conn, message(msgID, result(appExtendedResponse, resultProtocolError, "unsupported operation")))
		}
	}
}

func (d *fakeDir) handleBind(conn net.Conn, id int, msgID int64, op *ber.Packet) {
	if len(op.Children) < 3 {
		d.write(conn, message(msgID, result(appBindResponse, resultProtocolError, "malformed bind")))
		return
	}
	dn, _ := op.Children[1].Value.(string)
	password := op.Children[2].Data.String() // simple auth: [0] OCTET STRING
	d.recordBind(bindRec{conn: id, dn: dn, password: password})

	// An empty DN is an anonymous bind, which this directory allows.
	if dn == "" {
		d.write(conn, message(msgID, result(appBindResponse, resultSuccess, "")))
		return
	}
	if want, found := d.passwords[dn]; found && want == password {
		d.write(conn, message(msgID, result(appBindResponse, resultSuccess, "")))
		return
	}
	d.write(conn, message(msgID, result(appBindResponse, resultInvalidCreds, "invalid credentials")))
}

func (d *fakeDir) handleSearch(conn net.Conn, id int, msgID int64, op *ber.Packet) {
	if len(op.Children) < 8 {
		d.write(conn, message(msgID, result(appSearchResultDone, resultProtocolError, "malformed search")))
		return
	}
	base, _ := op.Children[0].Value.(string)
	rec := searchRec{conn: id, base: base}
	filter := op.Children[6]
	switch filter.Tag {
	case 3: // equalityMatch
		if len(filter.Children) == 2 {
			rec.filterAttr, _ = filter.Children[0].Value.(string)
			rec.filterValue, _ = filter.Children[1].Value.(string)
		}
	case 7: // present
		rec.present = true
		rec.filterAttr = filter.Data.String()
	}
	for _, a := range op.Children[7].Children {
		if s, ok := a.Value.(string); ok {
			rec.attrs = append(rec.attrs, s)
		}
	}
	d.recordSearch(rec)

	if d.emptyFor[base] {
		d.write(conn, message(msgID, result(appSearchResultDone, resultSuccess, "")))
		return
	}
	attrs, found := d.entries[base]
	if !found {
		d.write(conn, message(msgID, result(appSearchResultDone, resultNoSuchObject, "no such object")))
		return
	}
	// A base-scoped search returns the entry only when the filter matches it.
	if !rec.present && !hasValue(attrs[rec.filterAttr], rec.filterValue) {
		d.write(conn, message(msgID, result(appSearchResultDone, resultSuccess, "")))
		return
	}
	d.write(conn, message(msgID, entryPacket(base, attrs, rec.attrs)))
	d.write(conn, message(msgID, result(appSearchResultDone, resultSuccess, "")))
}

// handleExtended answers StartTLS. It returns the upgraded connection when the
// handshake succeeded, so the caller keeps reading from the encrypted stream.
func (d *fakeDir) handleExtended(conn net.Conn, msgID int64, op *ber.Packet) (net.Conn, error) {
	oid := ""
	if len(op.Children) > 0 {
		oid = op.Children[0].Data.String()
	}
	if oid != oidStartTLS {
		d.write(conn, message(msgID, result(appExtendedResponse, resultProtocolError, "unsupported extended operation")))
		return nil, nil
	}
	if !d.startTLS {
		d.write(conn, message(msgID, result(appExtendedResponse, resultUnwillingToPerf, "TLS not available")))
		return nil, nil
	}
	d.write(conn, message(msgID, result(appExtendedResponse, resultSuccess, "")))

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{d.cert}})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (d *fakeDir) write(conn net.Conn, p *ber.Packet) {
	if _, err := conn.Write(p.Bytes()); err != nil && !errors.Is(err, net.ErrClosed) {
		d.t.Logf("fake directory write: %v", err)
	}
}

// packet builders -----------------------------------------------------------

func message(id int64, op *ber.Packet) *ber.Packet {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	m.AppendChild(op)
	return m
}

// result builds an LDAPResult-shaped response (resultCode, matchedDN, message).
func result(appTag ber.Tag, code int64, diagnostic string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, "Result")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	return p
}

// entryPacket renders one entry, limited to the requested attributes.
func entryPacket(dn string, attrs map[string][]string, requested []string) *ber.Packet {
	e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResultEntry, nil, "SearchResultEntry")
	e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, name := range requested {
		values, found := attrs[name]
		if !found {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range values {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		}
		a.AppendChild(set)
		list.AppendChild(a)
	}
	e.AppendChild(list)
	return e
}

func hasValue(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// selfSignedCert generates a certificate for 127.0.0.1, used by the StartTLS
// test (the client verifies it only when insecure_skip_verify is off).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// closedPortURL returns an ldap:// URL nothing is listening on.
func closedPortURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "ldap://" + addr
}
