package quic

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/goburrow/quic/transport"
)

// Client is a client-side QUIC connection.
// All setters must only be invoked before calling Serve.
type Client struct {
	localConn
}

// NewClient creates a new QUIC client.
func NewClient(config *transport.Config) *Client {
	c := &Client{}
	c.localConn.init(config)
	return c
}

// ListenAndServe starts listening on UDP network address addr and
// serves incoming packets. Unlike Server.ListenAndServe, this function
// does not block as Serve is invoked in a goroutine.
func (s *Client) ListenAndServe(addr string) error {
	socket, err := net.ListenPacket("udp", addr)
	s.socket = socket
	if err == nil {
		go s.Serve()
	}
	return err
}

// Serve handles requests from given socket.
func (s *Client) Serve() error {
	if s.socket == nil {
		return errors.New("no listening connection")
	}
	s.logger.Log(LevelInfo, "listening %s", s.socket.LocalAddr())
	for {
		p := newPacket()
		n, addr, err := s.socket.ReadFrom(p.buf[:])
		if n > 0 {
			p.data = p.buf[:n]
			p.addr = addr
			s.logger.Log(LevelTrace, "%s receveid %d bytes\n%x", addr, n, p.data)
			s.recv(p)
		} else {
			freePacket(p)
		}
		if err != nil {
			return err
		}
	}
}

func (s *Client) recv(p *packet) {
	_, err := p.header.Decode(p.data, transport.MaxCIDLength)
	if err != nil {
		s.logger.Log(LevelInfo, "%s could not parse packet: %v", p.addr, err)
		freePacket(p)
		return
	}
	s.logger.Log(LevelDebug, "%s received packet %s", p.addr, &p.header)
	s.peersMu.RLock()
	if s.closing {
		// Server is closing
		s.peersMu.RUnlock()
		return
	}
	c, ok := s.peers[string(p.header.DCID)]
	s.peersMu.RUnlock()
	if ok {
		c.recvCh <- p
	} else {
		s.logger.Log(LevelDebug, "%s ignore unknown destination packet: %s", p.addr, &p.header)
		freePacket(p)
	}
}

// Connect establishes a new connection to UDP network address addr.
func (s *Client) Connect(addr string) error {
	c, err := s.newConn(addr)
	if err != nil {
		return err
	}
	s.peersMu.Lock()
	if s.closing {
		s.peersMu.Unlock()
		return fmt.Errorf("client is closed")
	}
	if _, ok := s.peers[string(c.scid[:])]; ok {
		s.peersMu.Unlock()
		return fmt.Errorf("connection id conflict scid=%x", c.scid)
	}
	s.peers[string(c.scid[:])] = c
	s.peersMu.Unlock()
	// Send initial packet
	p := newPacket()
	defer freePacket(p)
	if err = s.sendConn(c, p.buf[:maxDatagramSize]); err != nil {
		s.peersMu.Lock()
		delete(s.peers, string(c.scid[:]))
		s.peersMu.Unlock()
		return fmt.Errorf("send %s: %v", c.addr, err)
	}
	go s.handleConn(c)
	return nil
}

// Close closes all current establised connections and listening socket.
func (s *Client) Close() error {
	s.close(10 * time.Second)
	if s.socket != nil {
		return s.socket.Close()
	}
	return nil
}

func (s *Client) newConn(addr string) (*remoteConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c := newRemoteConn(udpAddr)
	if err = s.rand(c.scid[:]); err != nil {
		return nil, fmt.Errorf("generate connection id: %v", err)
	}
	c.conn, err = transport.Connect(c.scid[:], s.config)
	if err != nil {
		return nil, err
	}
	return c, nil
}
