package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	pb "node/pb/wg"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	host     = flag.String("host", "localhost", "Wireguard GRPC server host")
	port     = flag.Int("port", 8080, "Wireguard GRPC server port")
	certFile = flag.String("cert", "certs/client.crt", "path to RSA certificate")
	keyFile  = flag.String("key", "certs/client.key", "path to RSA Private key")
	caFile   = flag.String("ca", "certs/ca.crt", "path to CA certificate")
)

func printPeer(p *pb.Peer) {
	endpoint := net.UDPAddr{IP: p.Endpoint.GetIp(), Port: (int)(p.Endpoint.GetPort())}
	allowedIPs := make([]string, 0, len(p.AllowedIps))
	for _, ipn := range p.AllowedIps {
		ip := net.IPNet{IP: ipn.GetIp(), Mask: ipn.GetIpMask()}
		allowedIPs = append(allowedIPs, ip.String())
	}

	const f = `peer: %s
  endpoint: %s
  allowed ips: %s
  latest handshake: %s
  transfer: %d B received, %d B sent

`

	fmt.Printf(
		f,
		base64.StdEncoding.EncodeToString(p.GetPublicKey()),
		endpoint.String(),
		strings.Join(allowedIPs, ", "),
		p.LastHandshakeTime.AsTime(),
		p.RecievedBytes,
		p.TransmitBytes,
	)
}
func printDevice(d *pb.Device) {
	const f = `interface: %s (%s)
  public key: %s
  private key: (hidden)
  listening port: %d

`

	fmt.Printf(
		f,
		d.Name,
		d.Type.String(),
		base64.StdEncoding.EncodeToString(d.GetPublicKey()),
		d.ListenPort)
}

func main() {

	flag.Parse()

	// mTLS
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("read RSA key pair: %s", err)
	}
	ca, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read ca certificate: %s", err)
	}

	// Create a certificate pool with the CA
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append ca certs")
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName:   *host,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
		})),
	}

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	conn, err := grpc.DialContext(ctx, fmt.Sprintf("%s:%d", *host, *port), opts...)
	if err != nil {
		log.Fatalf("gRPC client connection: %v", err)
	}
	defer conn.Close()

	client := pb.NewWireGuardClient(conn)
	devices, err := client.Devices(ctx, &pb.DevicesRequest{})
	if err != nil {
		log.Fatalf("get devices: %v", err)
	}
	for _, dev := range devices.Devices {
		printDevice(dev)
		for _, peer := range dev.Peers {
			printPeer(peer)
		}
	}
	log.Println("done")
}
