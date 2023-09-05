package wgserver

import (
	"os"
	"testing"

	pb "github.com/atsevan/wireguard-grpc/pb/wg"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	cmpErrors = cmp.Comparer(func(x, y error) bool {
		return x.Error() == y.Error()
	})
)

func TestWGServerClose(t *testing.T) {
	var calls int
	fakeClose := func() error { calls++; return nil }
	wgs := WGServer{c: &testClient{CloseFunc: fakeClose}}
	if err := wgs.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}
	if diff := cmp.Diff(1, calls); diff != "" {
		t.Fatalf("unexpected number of clients closed (-want +got):\n%s", diff)
	}
}

func TestConfigureDevice(t *testing.T) {

	var (
		notExist = func(_ string, _ wgtypes.Config) error {
			return os.ErrNotExist
		}

		ok = func(_ string, _ wgtypes.Config) error {
			return nil
		}
		emptyCfg = &pb.Config{}

		cfg = &pb.Config{
			PrivateKey:   []byte("PrivateKey"),
			ListenPort:   8080,
			ReplacePeers: true,
			Peers: []*pb.PeerConfig{
				{
					PublicKey: []byte("PublicKey"),
				},
			},
		}
	)

	tests := []struct {
		name string
		cfg  *pb.Config
		fn   func(name string, cfg wgtypes.Config) error
		err  error
	}{
		{
			name: "not found",
			cfg:  emptyCfg,
			fn:   notExist,
			err:  os.ErrNotExist,
		}, {
			name: "empty cfg ok",
			cfg:  emptyCfg,
			fn:   ok,
			err:  nil,
		}, {
			name: "ok",
			cfg:  cfg,
			fn:   ok,
			err:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wgs := WGServer{c: &testClient{ConfigureDeviceFunc: tt.fn}}
			err := wgs.ConfigureDevice("", emptyCfg)
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDevices(t *testing.T) {
	var (
		clientOkFn = func() ([]*wgtypes.Device, error) {
			return []*wgtypes.Device{{Name: "wg0"}}, nil

		}
		clienNotFoundFn = func() ([]*wgtypes.Device, error) {
			return []*wgtypes.Device{}, os.ErrNotExist
		}
	)

	tests := []struct {
		name     string
		clientFn func() ([]*wgtypes.Device, error)
		err      error
		resp     []*pb.Device
	}{
		{
			name:     "ok",
			clientFn: clientOkFn,
			err:      nil,
			resp: []*pb.Device{
				{
					Name: "wg0",
				},
			},
		},
		{
			name:     "not found",
			clientFn: clienNotFoundFn,
			err:      os.ErrNotExist,
			resp:     []*pb.Device{},
		},
		{
			name: "skip failed",
			clientFn: func() ([]*wgtypes.Device, error) {
				return []*wgtypes.Device{{Name: "wg0"}, {Name: "wg1"}}, os.ErrNotExist
			},
			err:  os.ErrNotExist,
			resp: []*pb.Device{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wgs := WGServer{c: &testClient{DevicesFunc: tt.clientFn}}
			resp, err := wgs.Devices()
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(len(resp), len(tt.resp)); diff != "" {
				t.Fatalf("unexpected number of devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDevice(t *testing.T) {
	var (
		clientOkFn = func(name string) (*wgtypes.Device, error) {
			return &wgtypes.Device{Name: name}, nil

		}
		clienNotFoundFn = func(name string) (*wgtypes.Device, error) {
			return &wgtypes.Device{}, os.ErrNotExist
		}
	)

	tests := []struct {
		name     string
		in       string
		clientFn func(string) (*wgtypes.Device, error)
		err      error
		resp     *pb.Device
	}{
		{
			name:     "ok",
			in:       "wg0",
			clientFn: clientOkFn,
			err:      nil,
			resp:     &pb.Device{Name: "wg0"},
		},
		{
			name:     "not found",
			in:       "wg0",
			clientFn: clienNotFoundFn,
			err:      os.ErrNotExist,
			resp:     &pb.Device{},
		},
		{
			name:     "empty name",
			in:       "",
			clientFn: clientOkFn,
			err:      nil,
			resp:     &pb.Device{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wgs := WGServer{c: &testClient{DeviceFunc: tt.clientFn}}
			resp, err := wgs.Device(tt.in)
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(resp.Name, tt.resp.Name); diff != "" {
				t.Fatalf("unexpected name of devices (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConvertWGDeviceToPb(t *testing.T) {
	tests := []struct {
		name   string
		devIn  *wgtypes.Device
		devOut *pb.Device
		err    error
	}{
		{
			name:   "empty device",
			devIn:  &wgtypes.Device{},
			devOut: &pb.Device{},
			err:    nil,
		},
		{
			name: "OK device",
			devIn: &wgtypes.Device{
				Name:         "wg0",
				Type:         wgtypes.FreeBSDKernel,
				PrivateKey:   wgtypes.Key{},
				PublicKey:    wgtypes.Key{},
				ListenPort:   8080,
				FirewallMark: 1,
				Peers:        []wgtypes.Peer{{}},
			},
			devOut: &pb.Device{
				Name:         "wg0",
				Type:         pb.DeviceType_FREEBSD_KERNEL,
				PrivateKey:   []byte{},
				PublicKey:    []byte{},
				ListenPort:   8080,
				FirewallMark: 1,
				Peers:        []*pb.Peer{{}},
			},
			err: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := convertWGDeviceToPb(tt.devIn)
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.devOut.Name, resp.Name); diff != "" {
				t.Fatalf("unexpected name of devices (-want +got):\n%s", diff)
			}
		})
	}
}

type testClient struct {
	CloseFunc           func() error
	DevicesFunc         func() ([]*wgtypes.Device, error)
	DeviceFunc          func(name string) (*wgtypes.Device, error)
	ConfigureDeviceFunc func(name string, cfg wgtypes.Config) error
}

func (c *testClient) Close() error                        { return c.CloseFunc() }
func (c *testClient) Devices() ([]*wgtypes.Device, error) { return c.DevicesFunc() }
func (c *testClient) Device(name string) (*wgtypes.Device, error) {
	return c.DeviceFunc(name)
}

func (c *testClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.ConfigureDeviceFunc(name, cfg)
}
