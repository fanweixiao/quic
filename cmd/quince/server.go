package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/goburrow/quic"
	"github.com/goburrow/quic/transport"
)

func serverCommand(args []string) error {
	cmd := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := cmd.String("listen", "localhost:4433", "listen on the given IP:port")
	certFile := cmd.String("cert", "cert.crt", "TLS certificate path")
	keyFile := cmd.String("key", "cert.key", "TLS certificate key path")
	logLevel := cmd.Int("v", quic.LevelInfo, "log verbose level")
	enableRetry := cmd.Bool("retry", false, "enable address validation using Retry packet")
	cmd.Parse(args)

	fmt.Println("args ====== %v", args)

	config := newConfig()
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		config.TLS.Certificates = []tls.Certificate{cert}
	}
	server := quic.NewServer(config)
	server.SetHandler(&serverHandler{})
	server.SetLogger(quic.LeveledLogger(*logLevel))
	if *enableRetry {
		server.SetAddressValidator(quic.NewAddressValidator())
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		server.Close()
	}()
	return server.ListenAndServe(*listenAddr)
}

type serverHandler struct{}

func (s *serverHandler) Serve(c quic.Conn, events []interface{}) {
	for _, e := range events {
		log.Printf("%s connection event: %#v", c.RemoteAddr(), e)
		switch e := e.(type) {
		case transport.StreamRecvEvent:
			st := c.Stream(e.StreamID)
			if st != nil {
				p := make([]byte, 512)
				n, err := st.Read(p)
				if err != nil {
					panic(err)
				}
				fmt.Printf("----RECV-- %d bytes : %s\n", n, string(p[:n]))

				st.Write([]byte("pong!"))
				st.Close()
			}
		}
	}
}
