package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/goburrow/quic/transport"
)

// Server is a server-side QUIC connection.
// All setters must only be invoked before calling Serve.
type Server struct {
	localConn

	addrValid AddressValidator
}

// NewServer creates a new QUIC server.
func NewServer(config *transport.Config) *Server {
	s := &Server{}
	s.localConn.init(config)
	return s
}

// SetAddressValidator sets validation for QUIC connections address.
func (s *Server) SetAddressValidator(v AddressValidator) {
	s.addrValid = v
}

// ListenAndServe starts listening on UDP network address addr and
// serves incoming packets.
func (s *Server) ListenAndServe(addr string) error {
	socket, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.socket = socket
	return s.Serve()
}

// Serve handles incoming requests from a socket connection.
// XXX: Since net.PacketConn methods can be called simultaneously, users should be able to
// run Serve in multiple goroutines. For example:
//
// 	s.SetListen(socket)
// 	for i := 1; i < num; i++ {
// 		go s.Serve()
// 	}
// 	s.Serve() // main one blocking
func (s *Server) Serve() error {
	if s.socket == nil {
		return errors.New("no listening connection")
	}
	s.logger.Log(LevelInfo, "listening %s", s.socket.LocalAddr())
	for {
		p := newPacket()
		n, addr, err := s.socket.ReadFrom(p.buf[:])
		if n > 0 {
			// Process returned data first before considering error
			p.data = p.buf[:n]
			p.addr = addr
			s.logger.Log(LevelTrace, "%s received %d bytes\n%x", addr, n, p.data)
			s.recv(p)
		} else {
			freePacket(p)
		}
		if err != nil {
			// Stop on socket error.
			// FIXME: Should we stop on timeout when read deadline is set
			if err, ok := err.(net.Error); ok && err.Timeout() {
				s.logger.Log(LevelTrace, "read timeout: %v", err)
			} else {
				return err
			}
		}
	}
}

func (s *Server) recv(p *packet) {
	_, err := p.header.Decode(p.data, transport.MaxCIDLength)
	if err != nil {
		s.logger.Log(LevelDebug, "%s could not decode packet: %v", p.addr, err)
		freePacket(p)
		return
	}
	s.logger.Log(LevelDebug, "%s received packet %s", p.addr, &p.header)
	s.peersMu.RLock()
	if s.closing {
		// Do not process packet when closing
		s.peersMu.RUnlock()
		freePacket(p)
		return
	}
	c, ok := s.peers[string(p.header.DCID)]
	s.peersMu.RUnlock()
	if ok {
		c.recvCh <- p
	} else {
		// Server must ensure the any datagram packet containing Initial packet being at least 1200 bytes
		if p.header.Type != 0 || len(p.data) < transport.MinInitialPacketSize {
			s.logger.Log(LevelDebug, "%s dropped invalid initial packet: %s", p.addr, &p.header)
			freePacket(p)
			return
		}
		if p.header.Version != transport.ProtocolVersion {
			// Negotiate version
			s.negotiate(p.addr, &p.header)
			freePacket(p)
			return
		}
		go s.handleNewConn(p)
	}
}

func (s *Server) negotiate(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	n, err := transport.NegotiateVersion(p.buf[:], h.SCID, h.DCID)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate: %s %v", addr, h, err)
		return
	}
	n, err = s.socket.WriteTo(p.buf[:n], addr)
	if err != nil {
		s.logger.Log(LevelError, "%s negotiate: %s %v", addr, h, err)
		return
	}
	s.logger.Log(LevelDebug, "%s negotiate: newversion=%d %s", addr, transport.ProtocolVersion, h)
	s.logger.Log(LevelTrace, "%s sent %d bytes\n%x", addr, n, p.buf[:n])
}

func (s *Server) retry(addr net.Addr, h *transport.Header) {
	p := newPacket()
	defer freePacket(p)
	// newCID is a new DCID client shoud send in next Initial packet
	var newCID [transport.MaxCIDLength]byte
	if err := s.rand(newCID[:]); err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	// Set token to current header so it will be logged
	h.Token = s.addrValid.Generate(addr, h.DCID)
	n, err := transport.Retry(p.buf[:], h.SCID, newCID[:], h.DCID, h.Token)
	if err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	n, err = s.socket.WriteTo(p.buf[:n], addr)
	if err != nil {
		s.logger.Log(LevelError, "%s retry: %s %v", addr, h, err)
		return
	}
	s.logger.Log(LevelDebug, "%s retry: %v newcid=%x", addr, h, newCID)
	s.logger.Log(LevelTrace, "%s sent %d bytes\n%x", addr, n, p.buf[:n])
}

func (s *Server) verifyToken(addr net.Addr, token []byte) []byte {
	return s.addrValid.Validate(addr, token)
}

// handleNewConn creates a new connection and handles packets sent to this connection.
// Since verifying token and initializing a new connection can take a bit time,
// this method (instead of s.handleConn) is invoked in a new goroutine so that
// server can continue process other packets.
func (s *Server) handleNewConn(p *packet) {
	var odcid []byte
	if s.addrValid != nil {
		// Retry token
		if len(p.header.Token) == 0 {
			s.retry(p.addr, &p.header)
			freePacket(p)
			return
		}
		odcid = s.verifyToken(p.addr, p.header.Token)
		if len(odcid) == 0 {
			s.logger.Log(LevelInfo, "%s invalid retry token: %v", p.addr, &p.header)
			freePacket(p)
			return
		}
	}
	c, err := s.newConn(p.addr, p.header.DCID, odcid)
	if err != nil {
		s.logger.Log(LevelError, "%s create connection: %v", err)
		freePacket(p)
		return
	}
	s.peersMu.Lock()
	if s.closing {
		// Do not create a new handler when server is closing
		s.peersMu.Unlock()
		freePacket(p)
		return
	}
	if _, ok := s.peers[string(c.scid[:])]; ok {
		// Is that server too slow that client resent the packet? Log it as Error for now.
		s.peersMu.Unlock()
		s.logger.Log(LevelError, "%s connection id conflict scid=%x", p.addr, c.scid)
		freePacket(p)
		return
	}
	s.peers[string(c.scid[:])] = c
	s.peersMu.Unlock()
	s.logger.Log(LevelDebug, "%s new connection scid=%x odcid=%x", p.addr, c.scid, odcid)
	c.recvCh <- p // Buffered channel
	s.handleConn(c)
}

func (s *Server) newConn(addr net.Addr, scid, odcid []byte) (*remoteConn, error) {
	c := newRemoteConn(addr)
	var err error
	if len(scid) == len(c.scid) {
		copy(c.scid[:], scid)
	} else {
		// Generate id for new connection since short packets don't include CID length so
		// we use MaxCIDLength for all connections
		if err = s.rand(c.scid[:]); err != nil {
			return nil, err
		}
	}
	if c.conn, err = transport.Accept(c.scid[:], odcid, s.config); err != nil {
		return nil, err
	}
	return c, nil
}

// Close sends Close frame to all connected clients and closes the socket given in Serve.
// Note: if Close is called before Serve, the socket may not be set so it will not be close.
// In that case Serve will hang until it gets socket read error.
func (s *Server) Close() error {
	s.close(30 * time.Second)
	if s.socket != nil {
		// Closing socket should unblock Serve
		return s.socket.Close()
	}
	return nil
}

// AddressValidator generates and validates server retry token.
// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#token-integrity
type AddressValidator interface {
	// Generate creates a new token from given addr and odcid.
	Generate(addr net.Addr, odcid []byte) []byte
	// Validate returns odcid when the address and token pair is valid,
	// empty slice otherwize.
	Validate(addr net.Addr, token []byte) []byte
}

// NewAddressValidator returns a simple implementation of AddressValidator.
// It encrypts client original CID into token which is valid for 10 seconds.
func NewAddressValidator() AddressValidator {
	s, err := newAddressValidator()
	if err != nil {
		panic(err)
	}
	return s
}

// addressValidator implements AddressValidator.
// The token include ODCID encrypted using AES-GSM AEAD with a randomly-generated key.
type addressValidator struct {
	aead   cipher.AEAD
	nonce  []byte // First 4 bytes is current time
	timeFn func() time.Time
}

// NewAddressValidator creates a new AddressValidator or returns error when failed to
// generate secret or AEAD.
func newAddressValidator() (*addressValidator, error) {
	var key [16]byte
	_, err := rand.Read(key[:])
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return &addressValidator{
		aead:   aead,
		nonce:  nonce,
		timeFn: time.Now,
	}, nil
}

// Generate encrypts odcid using current time as nonce and addr as additional data.
func (s *addressValidator) Generate(addr net.Addr, odcid []byte) []byte {
	now := s.timeFn().Unix()
	nonce := make([]byte, len(s.nonce))
	binary.BigEndian.PutUint32(nonce, uint32(now))
	copy(nonce[4:], s.nonce[4:])

	token := make([]byte, 4+len(odcid)+s.aead.Overhead())
	binary.BigEndian.PutUint32(token, uint32(now))
	s.aead.Seal(token[4:4], nonce, odcid, []byte(addr.String()))
	return token
}

// Validate decrypts token and returns odcid.
func (s *addressValidator) Validate(addr net.Addr, token []byte) []byte {
	if len(token) < 4 {
		return nil
	}
	const validity = 10 // Second
	now := s.timeFn().Unix()
	issued := int64(binary.BigEndian.Uint32(token))
	if issued < now-validity || issued > now {
		// TODO: Fix overflow when time > MAX_U32
		return nil
	}
	nonce := make([]byte, len(s.nonce))
	copy(nonce, token[:4])
	copy(nonce[4:], s.nonce[4:])
	odcid, err := s.aead.Open(nil, nonce, token[4:], []byte(addr.String()))
	if err != nil {
		return nil
	}
	return odcid
}
