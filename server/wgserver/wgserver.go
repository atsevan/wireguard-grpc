package wgserver

import (
	"log"
	"net"

	pb "node/pb/wg"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// WGServer keeps data about wireguard server
type WGServer struct {
	c *wgctrl.Client
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

// ConfigureDevice configures a WireGuard device by its interface name.
//
// If the device specified by name does not exist or is not a WireGuard device,
// an error is returned which can be checked using `errors.Is(err, os.ErrNotExist)`.
func (wgs WGServer) ConfigureDevice(name string, cfg *pb.Config) error {
	listenPort := int(cfg.ListenPort)
	fwMark := int(cfg.FirewallMark)
	peers := []wgtypes.PeerConfig{}
	for _, p := range cfg.Peers {
		keppaliveInterval := p.PersistentKeepaliveInterval.AsDuration()
		endpoint := net.UDPAddr{IP: net.IP(p.Endpoint.Ip), Port: int(p.Endpoint.Port), Zone: p.Endpoint.Zone}
		allowedIps := []net.IPNet{}
		for _, ip := range allowedIps {
			allowedIps = append(allowedIps, net.IPNet{
				IP:   ip.IP,
				Mask: ip.Mask,
			})
		}
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:                   wgtypes.Key(p.PublicKey),
			Remove:                      p.Remove,
			UpdateOnly:                  p.UpdateOnly,
			PresharedKey:                (*wgtypes.Key)(p.PresharedKey),
			Endpoint:                    &endpoint,
			PersistentKeepaliveInterval: &keppaliveInterval,
			ReplaceAllowedIPs:           p.ReplaceAllowedIps,
			AllowedIPs:                  allowedIps,
		})
	}
	wgCfg := wgtypes.Config{
		PrivateKey:   (*wgtypes.Key)(cfg.GetPrivateKey()),
		ListenPort:   &listenPort,
		FirewallMark: &fwMark,
		ReplacePeers: cfg.ReplacePeers,
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