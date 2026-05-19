// Minimal TCP→VSOCK forwarder for the attestation enclave host.
//
// The Nitro enclave listens on VSOCK port 3000 (axum-served HTTP). The host
// exposes a TCP listener on :8080 and forwards every accepted connection to
// the enclave over VSOCK.
//
// Run:
//
//	go run ./proxy --vsock-cid <enclave_cid> --vsock-port 3000 --tcp 0.0.0.0:8080
//
// The CID is the enclave's context ID, obtained from `nitro-cli describe-enclaves`.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/mdlayher/vsock"
)

func main() {
	vsockCID := flag.Uint("vsock-cid", 0, "enclave VSOCK CID (from `nitro-cli describe-enclaves`)")
	vsockPort := flag.Uint("vsock-port", 3000, "enclave VSOCK port")
	tcpAddr := flag.String("tcp", "0.0.0.0:8080", "TCP address to listen on")
	flag.Parse()

	if *vsockCID == 0 {
		fmt.Fprintln(os.Stderr, "must pass --vsock-cid (see `nitro-cli describe-enclaves`)")
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", *tcpAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *tcpAddr, err)
	}
	log.Printf("listening on %s, forwarding to VSOCK %d:%d", *tcpAddr, *vsockCID, *vsockPort)

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(client, uint32(*vsockCID), uint32(*vsockPort))
	}
}

func handle(client net.Conn, cid, port uint32) {
	defer client.Close()
	enc, err := vsock.Dial(cid, port, nil)
	if err != nil {
		log.Printf("vsock dial %d:%d: %v", cid, port, err)
		return
	}
	defer enc.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(enc, client); done <- struct{}{} }()
	go func() { io.Copy(client, enc); done <- struct{}{} }()
	<-done
}
