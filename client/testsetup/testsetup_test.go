package testsetup

import (
	"context"
	"os"
	"testing"

	pb "github.com/atsevan/wireguard-grpc/pb/wg"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
)

var (
	cmpErrors = cmp.Comparer(func(x, y error) bool {
		return x.Error() == y.Error()
	})
)

func TestNewTestWGSetup(t *testing.T) {
	wgs, err := NewTestWGSetup(pb.NewWireGuardClient(&grpc.ClientConn{}), "wg0", 51280)
	if err != nil {
		t.Fatalf("NewTestWGSetup: %s", err)
	}
	if wgs.PublicKey != wgs.serverPrivateKey.PublicKey() {
		t.Errorf("PublicKey and PrivateKey doesn't match")
	}
}

func TestInitWGDevice(t *testing.T) {
	var (
		clientOk = testClient{
			ConfigureDeviceFunc: func(ctx context.Context, in *pb.ConfigureDeviceRequest, opts ...grpc.CallOption) (*pb.ConfigureDeviceResponse, error) {
				return &pb.ConfigureDeviceResponse{}, nil
			},
		}
		clientNotOk = testClient{
			ConfigureDeviceFunc: func(ctx context.Context, in *pb.ConfigureDeviceRequest, opts ...grpc.CallOption) (*pb.ConfigureDeviceResponse, error) {
				return &pb.ConfigureDeviceResponse{}, os.ErrNotExist
			},
		}
	)
	tests := []struct {
		name   string
		client pb.WireGuardClient
		err    error
	}{
		{
			name:   "OK",
			client: clientOk,
			err:    nil,
		},
		{
			name:   "NotOk",
			client: clientNotOk,
			err:    os.ErrNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wgs, _ := NewTestWGSetup(tt.client, "wg0", 51280)
			err := wgs.InitWGDevice(context.Background())
			if diff := cmp.Diff(tt.err, err, cmpErrors); diff != "" {
				t.Fatalf("unexpected error (-want +got):\n%s", diff)
			}
		})
	}
}

type testClient struct {
	CloseFunc           func() error
	DevicesFunc         func(ctx context.Context, in *pb.DevicesRequest, opts ...grpc.CallOption) (*pb.DevicesResponse, error)
	DeviceFunc          func(ctx context.Context, in *pb.DeviceRequest, opts ...grpc.CallOption) (*pb.DeviceResponse, error)
	ConfigureDeviceFunc func(ctx context.Context, in *pb.ConfigureDeviceRequest, opts ...grpc.CallOption) (*pb.ConfigureDeviceResponse, error)
}

func (c testClient) Close() error { return c.CloseFunc() }

func (c testClient) Devices(ctx context.Context, in *pb.DevicesRequest, opts ...grpc.CallOption) (*pb.DevicesResponse, error) {
	return c.DevicesFunc(ctx, in, opts...)
}

func (c testClient) Device(ctx context.Context, in *pb.DeviceRequest, opts ...grpc.CallOption) (*pb.DeviceResponse, error) {
	return c.DeviceFunc(ctx, in, opts...)
}

func (c testClient) ConfigureDevice(ctx context.Context, in *pb.ConfigureDeviceRequest, opts ...grpc.CallOption) (*pb.ConfigureDeviceResponse, error) {
	return c.ConfigureDeviceFunc(ctx, in, opts...)
}
