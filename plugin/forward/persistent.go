package forward

import (
	"crypto/tls"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns"
)

// a persistConn hold the dns.Conn and the last used time.
type persistConn struct {
	c    *dns.Conn
	used time.Time
}

// transport hold the persistent cache.
type transport struct {
	conns     map[string]map[int64]*persistConn //  Buckets for udp, tcp and tcp-tls, then (random) numbers -> *persistConn
	expire    time.Duration                     // After this duration a connection is expired.
	addr      string
	tlsConfig *tls.Config

	dial  chan string
	yield chan *dns.Conn
	ret   chan *dns.Conn
	stop  chan bool
}

func newTransport(addr string, tlsConfig *tls.Config) *transport {
	t := &transport{
		conns:  make(map[string]map[int64]*persistConn),
		expire: defaultExpire,
		addr:   addr,
		dial:   make(chan string),
		yield:  make(chan *dns.Conn),
		ret:    make(chan *dns.Conn),
		stop:   make(chan bool),
	}
	t.conns["udp"] = make(map[int64]*persistConn)
	t.conns["tcp"] = make(map[int64]*persistConn)
	t.conns["tcp-tls"] = make(map[int64]*persistConn)

	go func() { t.connManager() }()
	return t
}

// connManagers manages the persistent connection cache for UDP and TCP.
func (t *transport) connManager() {

Wait:
	for {
		select {
		case proto := <-t.dial:
			// Yes O(n), shouldn't put millions in here. We walk all connection until we find the first
			// one that is usuable.

			ma := t.conns[proto]
			for k, pc := range ma {
				if time.Since(pc.used) < t.expire {
					// Found one, remove from pool and return this conn.
					delete(ma, k)
					t.ret <- pc.c
					continue Wait
				}
				// This conn has expired. Close it.
				pc.c.Close()
				delete(ma, k)
			}

			t.ret <- nil

		case conn := <-t.yield:

			//			SocketGauge.WithLabelValues(t.addr).Set(float64(t.len() + 1))

			key := rand.Int63()

			// no proto here, infer from config and conn
			if _, ok := conn.Conn.(*net.UDPConn); ok {
				t.conns["udp"][key] = &persistConn{conn, time.Now()}
				continue Wait
			}

			if t.tlsConfig == nil {
				t.conns["tcp"][key] = &persistConn{conn, time.Now()}
				continue Wait
			}

			t.conns["tcp-tls"][key] = &persistConn{conn, time.Now()}

		case <-t.stop:
			close(t.ret)
			return
		}
	}
}

// Dial dials the address configured in transport, potentially reusing a connection or creating a new one.
func (t *transport) Dial(proto string) (*dns.Conn, bool, error) {
	// If tls has been configured; use it.
	if t.tlsConfig != nil {
		proto = "tcp-tls"
	}

	t.dial <- proto
	c := <-t.ret

	if c != nil {
		return c, true, nil
	}

	if proto == "tcp-tls" {
		conn, err := dns.DialTimeoutWithTLS("tcp", t.addr, t.tlsConfig, dialTimeout)
		return conn, false, err
	}
	conn, err := dns.DialTimeout(proto, t.addr, dialTimeout)
	return conn, false, err
}

// Yield return the connection to transport for reuse.
func (t *transport) Yield(c *dns.Conn) { t.yield <- c }

// Stop stops the transport's connection manager.
func (t *transport) Stop() { close(t.stop) }

// SetExpire sets the connection expire time in transport.
func (t *transport) SetExpire(expire time.Duration) { t.expire = expire }

// SetTLSConfig sets the TLS config in transport.
func (t *transport) SetTLSConfig(cfg *tls.Config) { t.tlsConfig = cfg }

const defaultExpire = 10 * time.Second
