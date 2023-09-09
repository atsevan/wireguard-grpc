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
	"os"
	"strings"
	"time"

	"github.com/atsevan/wireguard-grpc/client/testsetup"
	pb "github.com/atsevan/wireguard-grpc/pb/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	host         = flag.String("host", "localhost", "Wireguard GRPC server host")
	port         = flag.Int("port", 8080, "Wireguard GRPC server port")
	certFile     = flag.String("cert", "certs/client.crt", "path to RSA certificate")
	keyFile      = flag.String("key", "certs/client.key", "path to RSA Private key")
	caFile       = flag.String("ca", "certs/ca.crt", "path to CA certificate")
	insecureFlag = flag.Bool("insecure", false, "no credentials in use")
	confDevice   = flag.Bool("configuretest", false, "configure 'wg0' device and add a peer")
)

const (
	peerTmpl = `peer: %s
	endpoint: %s
	allowed ips: %s
	latest handshake: %s
	transfer: %d B received, %d B sent

  `
	deviceTmpl = `interface: %s (%s)
  public key: %s
  private key: (hidden)
  listening port: %d

  `
	peerConfigTmpl = `
  [Interface]
  PrivateKey = %s
  Address = %s/24

  [Peer]
  PublicKey = %s
  AllowedIPs = 0.0.0.0/0, ::/0
  Endpoint = %s:%d
  `
)

func printPeer(p *pb.Peer) {
	endpoint := net.UDPAddr{
		IP:   p.Endpoint.GetIp(),
		Port: (int)(p.Endpoint.GetPort()),
	}
	allowedIPs := make([]string, 0, len(p.AllowedIps))
	for _, ipn := range p.AllowedIps {
		ip := net.IPNet{IP: ipn.GetIp(), Mask: ipn.GetIpMask()}
		allowedIPs = append(allowedIPs, ip.String())
	}
	fmt.Printf(
		peerTmpl,
		base64.StdEncoding.EncodeToString(p.GetPublicKey()),
		endpoint.String(),
		strings.Join(allowedIPs, ", "),
		p.LastHandshakeTime.AsTime(),
		p.RecievedBytes,
		p.TransmitBytes,
	)
}

func printDevice(d *pb.Device) {
	fmt.Printf(
		deviceTmpl,
		d.Name,
		d.Type.String(),
		base64.StdEncoding.EncodeToString(d.GetPublicKey()),
		d.ListenPort)
}

// transportCredentialsFromTLS creates TransportCredentials based on TLS certificate
func transportCredentialsFromTLS(certPath string, keyPath string, caPath string, serverName string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read RSA key pair: %s", err)
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %s", err)
	}

	// Create a certificate pool and append the client certificates from the CA
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, fmt.Errorf("failed to append client certs")
	}
	return credentials.NewTLS(&tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	}), nil
}

func main() {

	flag.Parse()

	var err error
	var creds credentials.TransportCredentials

	if *insecureFlag == true {
		log.Println("No transport security in use")
		creds = insecure.NewCredentials()
	} else {
		creds, err = transportCredentialsFromTLS(*certFile, *keyFile, *caFile, *host)
		if err != nil {
			log.Fatalf("trasport credentials from TLS: %s", err)
		}
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	ctx, cancelCtx := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCtx()

	conn, err := grpc.DialContext(ctx, fmt.Sprintf("%s:%d", *host, *port), opts...)
	if err != nil {
		log.Fatalf("gRPC client connection: %v", err)
	}
	defer conn.Close()

	client := pb.NewWireGuardClient(conn)

	if *confDevice == true {
		ip := net.ParseIP("192.168.2.2")
		devName := "wg0"
		listenPort := int32(51820)

		wgSetup, err := testsetup.NewTestWGSetup(client, devName, listenPort)
		if err != nil {
			log.Fatalf("create Wireguard setup: %v", err)
		}

		err = wgSetup.InitWGDevice(ctx)
		if err != nil {
			log.Fatalf("create Wireguard setup: %v", err)
		}

		peerPrivateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Fatalf("generate peer key: %v", err)
		}
		peerPublicKey := peerPrivateKey.PublicKey()

		peer := &pb.PeerConfig{
			PublicKey: peerPublicKey[:],
			AllowedIps: []*pb.IPNet{
				{
					Ip:     ip,
					IpMask: net.CIDRMask(32, 32), // /32 mask
				},
			},
			ReplaceAllowedIps: true,
		}
		err = wgSetup.AddPeer(ctx, peer)
		if err != nil {
			log.Fatalf("add peer: %s", err)
		}

		fmt.Printf(
			peerConfigTmpl,
			peerPrivateKey,
			ip,
			wgSetup.PublicKey,
			*host,
			listenPort,
		)
	}

	// print peers from all devices
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
