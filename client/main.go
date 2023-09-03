package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	pb "node/pb/wg"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var serverAddress = flag.String("server", "localhost:8080", "Wireguard GRPC server address")

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

	conn, err := grpc.Dial(*serverAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewWireGuardClient(conn)
	devices, err := client.Devices(context.Background(), &pb.DevicesRequest{})
	if err != nil {
		log.Fatalf("failed to get devices: %v", err)
	}
	for _, dev := range devices.Devices {
		printDevice(dev)
		for _, peer := range dev.Peers {
			printPeer(peer)
		}
	}
}
