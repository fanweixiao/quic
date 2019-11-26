package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func clientCommand(args []string) error {
	cmd := flag.NewFlagSet("client", flag.ExitOnError)
	listenAddr := cmd.String("listen", "0.0.0.0:0", "listen on the given IP:port")
	certVerify := cmd.Bool("verify", true, "listen on the given IP:port")
	cmd.Parse(args)

	addr := cmd.Arg(0)
	if addr == "" {
		fmt.Fprintln(cmd.Output(), "Usage: quince client [options] <address>")
		cmd.PrintDefaults()
		return nil
	}
	config := newConfig()
	config.TLS.ServerName = serverName(addr)
	config.TLS.InsecureSkipVerify = !*certVerify
	handler := clientHandler{}
	client := quic.NewClient(config, &handler)
	if err := client.Listen(*listenAddr); err != nil {
		return err
	}
	if err := client.Connect(addr); err != nil {
		return err
	}
	handler.wg.Wait()
	return nil
}

type clientHandler struct {
	wg   sync.WaitGroup
	sent bool
}

func (s *clientHandler) Created(c quic.Conn) error {
	s.wg.Add(1)
	return nil
}

func (s *clientHandler) Serve(c quic.Conn) {
	if !s.sent {
		st := c.Stream(4)
		st.Write([]byte("GET /\r\n"))
		st.Close()
		s.sent = true
	}
	for _, e := range c.Events() {
		log.Printf("%s connection event: %#v", c.RemoteAddr(), e)
		switch e := e.(type) {
		case *transport.StreamEvent:
			st := c.Stream(e.StreamID)
			buf := make([]byte, 512)
			n, _ := st.Read(buf)
			log.Printf("stream %d received: %s", e.StreamID, buf[:n])
		}
	}
}

func (s *clientHandler) Closed(c quic.Conn) {
	log.Printf("%s connection closed", c.RemoteAddr())
	s.wg.Done()
}

func serverName(s string) string {
	colon := strings.LastIndex(s, ":")
	if colon > 0 {
		bracket := strings.LastIndex(s, "]")
		if colon > bracket {
			return s[:colon]
		}
	}
	return s
}
