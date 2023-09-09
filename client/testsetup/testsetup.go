package testsetup

import (
	"context"
	"fmt"

	pb "github.com/atsevan/wireguard-grpc/pb/wg"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestWGSetup keeps data about the Wireguard setup
type TestWGSetup struct {
	client           pb.WireGuardClient
	interfaceName    string
	serverPrivateKey wgtypes.Key
	PublicKey        wgtypes.Key
	listenPort       int32
}

// NewTestWGSetup creates a TestWGSetup
func NewTestWGSetup(client pb.WireGuardClient, interfaceName string, listenPort int32) (*TestWGSetup, error) {
	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return &TestWGSetup{}, fmt.Errorf("generate private key: %s", err)
	}
	return &TestWGSetup{
		client:           client,
		serverPrivateKey: serverPrivateKey,
		interfaceName:    interfaceName,
		PublicKey:        serverPrivateKey.PublicKey(),
		listenPort:       listenPort,
	}, nil
}

// InitWGDevice configure the wireguard device
//
// It expects that the wireguard device exists.
// For Linux it can be configured like:
//
//	sudo ip link add dev wg0 type wireguard
//	sudo ip address add 192.168.2.1/24 dev wg0
//	sudo ip link set up dev wg0
func (s *TestWGSetup) InitWGDevice(ctx context.Context) error {
	_, err := s.client.ConfigureDevice(ctx, &pb.ConfigureDeviceRequest{
		Name: s.interfaceName,
		Config: &pb.Config{
			PrivateKey:   s.serverPrivateKey[:],
			ListenPort:   s.listenPort,
			Peers:        []*pb.PeerConfig{},
			ReplacePeers: true,
		},
	})
	return err
}

// AddPeer adds a new peer
func (s *TestWGSetup) AddPeer(ctx context.Context, peer *pb.PeerConfig) error {
	_, err := s.client.ConfigureDevice(ctx, &pb.ConfigureDeviceRequest{
		Name: s.interfaceName,
		Config: &pb.Config{
			PrivateKey: s.serverPrivateKey[:],
			ListenPort: s.listenPort,
			Peers:      []*pb.PeerConfig{peer},
		},
	})
	return err
}
