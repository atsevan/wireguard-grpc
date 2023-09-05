# Wireguard gRPC Service 

Wireguard gRPC aimed at managing Wireguard configurations. 
The service gives a control over Wireguard setup via gRPC using native client without parsing output of wireguard-tools like `wg` and `wg-quick`.

Client example is at [client/main.go](client/main.go)

# Build

Run the server with mTLS
```
make cert  # generate localhost certs for mutual authentication (mTLS)
make build  # build a binary
sudo ./wireguard-grpc  # run the server
```

Run the client
```
go run client/main.go
```

# Development

Run without TLS
```
# go run server/main.go -insecure  # run the server w/o TLS
```

```
$ go run client/main.go -insecure  # run the client w/o TLS
```

Explore API with `grpcurl`
```
$ grpcurl -plaintext localhost:8080 describe WireGuard
WireGuard is a service:
service WireGuard {
  rpc ConfigureDevice ( .ConfigureDeviceRequest ) returns ( .ConfigureDeviceResponse );
  rpc Device ( .DeviceRequest ) returns ( .DeviceResponse );
  rpc Devices ( .DevicesRequest ) returns ( .DevicesResponse );
}
```


# WIP: GCP free-tier instance test
```
# create an instance
gcloud compute instances create vpn-test-instance-1 --machine-type=e2-micro --zone=us-east1-c

# enable ip_forwarding and setup a wg interface
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --command="sudo sysctl 'net.ipv4.ip_forward=1'; sudo ip link add dev wg0 type wireguard; sudo ip link set up dev wg0" 


# download and run *insecure* wireguard-grpc with port-frowarding to localhost for grpc and wireguard
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --ssh-flag="-vv" --ssh-flag="-L 8080:localhost:8080 -L 51820:localhost:51820" \
    --command="wget https://github.com/atsevan/wireguard-grpc/releases/download/v0.0.1/wireguard-grpc-linux && chmod +x wireguard-grpc-linux && sudo ./wireguard-grpc-linux -insecure"

## open a new terminal
go run client/main.go -configuredevice -insecure

# destroy the instance
gcloud compute instances delete vpn-test-instance-1 --zone=us-east1-c --quiet
```