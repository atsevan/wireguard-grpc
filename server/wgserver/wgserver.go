package wgserver

import (
	"io"
	"log"
	"net"
	"os"

	pb "github.com/atsevan/wireguard-grpc/pb/wg"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// WGClient represents the wireguard client
type WGClient interface {
	io.Closer
	ConfigureDevice(string, wgtypes.Config) error
	Device(string) (*wgtypes.Device, error)
	Devices() ([]*wgtypes.Device, error)
}

// WGServer keeps data about wireguard server
type WGServer struct {
	c WGClient
	d *wgtypes.Device
}

// NewWGServer creates a new instance of WGServer
func NewWGServer() (WGServer, error) {
	wgs := &WGServer{}
	c, err := wgctrl.New()
	if err != nil {
		log.Printf("WGServer.NewWGServer: %s", err)
		return *wgs, err
	}
	wgs.c = c
	return *wgs, nil
}

// Close releases resources used by a WGServer.
func (wgs WGServer) Close() error {
	return wgs.c.Close()
}

func pb2UDPAddr(pbUDP *pb.UDPAddr) *net.UDPAddr {
	if pbUDP == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   net.IP(pbUDP.GetIp()),
		Port: int(pbUDP.GetPort()),
		Zone: pbUDP.GetZone(),
	}
}

func pbKey2wgKey(key []byte) *wgtypes.Key {
	if key == nil {
		return nil
	}
	return (*wgtypes.Key)(key)
}

// ConfigureDevice configures a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`
// os.ErrInvalid is returned on invalid input.
func (wgs WGServer) ConfigureDevice(name string, cfg *pb.Config) error {
	if name == "" {
		return os.ErrInvalid
	}

	listenPort := int(cfg.GetListenPort())
	fwMark := int(cfg.GetFirewallMark())

	peers := []wgtypes.PeerConfig{}
	for _, p := range cfg.GetPeers() {
		keppaliveInterval := p.GetPersistentKeepaliveInterval().AsDuration()

		allowedIps := []net.IPNet{}
		for _, ip := range p.AllowedIps {
			allowedIps = append(allowedIps, net.IPNet{
				IP:   ip.GetIp(),
				Mask: ip.GetIpMask(),
			})
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:                   *pbKey2wgKey(p.PublicKey),
			Remove:                      p.GetRemove(),
			UpdateOnly:                  p.GetUpdateOnly(),
			PresharedKey:                pbKey2wgKey(p.PresharedKey),
			Endpoint:                    pb2UDPAddr(p.Endpoint),
			PersistentKeepaliveInterval: &keppaliveInterval,
			ReplaceAllowedIPs:           p.GetReplaceAllowedIps(),
			AllowedIPs:                  allowedIps,
		})
	}
	wgCfg := wgtypes.Config{
		PrivateKey:   pbKey2wgKey(cfg.PrivateKey),
		ListenPort:   &listenPort,
		FirewallMark: &fwMark,
		ReplacePeers: cfg.GetReplacePeers(),
		Peers:        peers,
	}

	return wgs.c.ConfigureDevice(name, wgCfg)
}

// Devices retrieves all WireGuard devices on this system.
func (wgs WGServer) Devices() ([]*pb.Device, error) {
	devices, err := wgs.c.Devices()
	if err != nil {
		return []*pb.Device{}, err
	}
	pbDevices := []*pb.Device{}
	for _, dev := range devices {
		pbDev, err := convertWGDeviceToPb(dev)
		if err != nil {
			log.Printf("Converting to PB: %s", err)
			continue
		}
		pbDevices = append(pbDevices, pbDev)
	}
	return pbDevices, err
}

// Device retrieves a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (wgs WGServer) Device(name string) (*pb.Device, error) {
	if name == "" {
		return &pb.Device{}, os.ErrInvalid
	}
	dev, err := wgs.c.Device(name)
	if err != nil {
		return &pb.Device{}, err
	}
	pbDevice, err := convertWGDeviceToPb(dev)
	if err != nil {
		log.Printf("Converting to PB: %s", err)
		return &pb.Device{}, err
	}
	return pbDevice, nil
}

// convertWGDeviceToPb converts wgtypes.Device into pb.Device
func convertWGDeviceToPb(dev *wgtypes.Device) (*pb.Device, error) {
	peers := []*pb.Peer{}
	for _, p := range dev.Peers {
		endpoint := &pb.UDPAddr{}
		if p.Endpoint != nil {
			endpoint = &pb.UDPAddr{
				Ip:   []byte(p.Endpoint.IP),
				Port: int32(p.Endpoint.AddrPort().Port()),
				Zone: p.Endpoint.Zone,
			}
		}
		allowedIPs := []*pb.IPNet{}
		for _, ip := range p.AllowedIPs {
			allowedIPs = append(allowedIPs, &pb.IPNet{
				Ip:     ip.IP,
				IpMask: ip.Mask,
			})
		}
		protoVersion := int32(p.ProtocolVersion)
		peers = append(peers, &pb.Peer{
			PublicKey:                   p.PublicKey[:],
			PresharedKey:                p.PresharedKey[:],
			Endpoint:                    endpoint,
			PersistentKeepaliveInterval: durationpb.New(p.PersistentKeepaliveInterval),
			LastHandshakeTime:           timestamppb.New(p.LastHandshakeTime),
			RecievedBytes:               p.ReceiveBytes,
			TransmitBytes:               p.TransmitBytes,
			AllowedIps:                  allowedIPs,
			ProtocolVersion:             protoVersion,
		})
	}
	return &pb.Device{
		Name:         dev.Name,
		Type:         pb.DeviceType(dev.Type),
		PrivateKey:   dev.PrivateKey[:],
		PublicKey:    dev.PublicKey[:],
		ListenPort:   int32(dev.ListenPort),
		FirewallMark: int32(dev.FirewallMark),
		Peers:        peers,
	}, nil
}
