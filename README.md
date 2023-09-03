# Wireguard gRPC Service 

Wireguard gRPC aimed at managing Wireguard configurations . The idea is to have a control over Wireguard setup via gRPC using native client without parsing output of wireguard-tools like wg and wg-quick.

# Development

Run the server
```
make build-linux
sudo ./wireguard-grpc-linux
```

Client example is at [client/main.go](client/main.go)