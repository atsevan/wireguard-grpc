package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	pb "node/pb/wg"
	"node/server/wgserver"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	host     = flag.String("host", "localhost", "host to listen to")
	port     = flag.Int("port", 8080, "port to listen to")
	certFile = flag.String("cert", "certs/server.crt", "path to RSA certificate")
	keyFile  = flag.String("key", "certs/server.key", "path to RSA Private key")
	caFile   = flag.String("ca", "certs/ca.crt", "path to CA certificate")
)

// NodeManagerServer is a proto generated server
type NodeManagerServer struct {
	pb.UnimplementedWireGuardServer
	wgs WireguardServer
}

// WireguardServer defines an interface to the Wireguard server
type WireguardServer interface {
	io.Closer
	ConfigureDevice(string, *pb.Config) error
	Devices() ([]*pb.Device, error)
	Device(string) (*pb.Device, error)
}

// ConfigureDevice configures a WireGuard device by its interface name.
func (s *NodeManagerServer) ConfigureDevice(ctx context.Context, in *pb.ConfigureDeviceRequest) (*pb.ConfigureDeviceResponse, error) {
	err := s.wgs.ConfigureDevice(in.GetName(), in.GetConfig())
	return &pb.ConfigureDeviceResponse{}, err
}

// Device retrieves a WireGuard device by its interface name.
func (s *NodeManagerServer) Device(ctx context.Context, in *pb.DeviceRequest) (*pb.DeviceResponse, error) {
	dev, err := s.wgs.Device(in.GetName())
	return &pb.DeviceResponse{
		Device: dev,
	}, err
}

// Devices retrieves all WireGuard devices on this system.
func (s *NodeManagerServer) Devices(ctx context.Context, in *pb.DevicesRequest) (*pb.DevicesResponse, error) {
	devices, err := s.wgs.Devices()
	return &pb.DevicesResponse{
		Devices: devices,
	}, err
}

func main() {
	flag.Parse()
	wgs, err := wgserver.NewWGServer()
	if err != nil {
		log.Fatalf("NewWGServer: %v", err)
	}
	defer wgs.Close()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("listen to %s", addr)

	// mTLS
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("read RSA key pair: %s", err)
	}
	ca, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA certificate: %s", err)
	}

	// Create a certificate pool and append the client certificates from the CA
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		log.Fatalf("failed to append client certs")
	}

	opts := []grpc.ServerOption{
		grpc.Creds( // Create the TLS credentials
			credentials.NewTLS(&tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{certificate},
				ClientCAs:    certPool,
			},
			)),
	}
	s := grpc.NewServer(opts...)
	reflection.Register(s)
	nms := &NodeManagerServer{
		wgs: wgs,
	}
	pb.RegisterWireGuardServer(s, nms)
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
