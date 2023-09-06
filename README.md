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