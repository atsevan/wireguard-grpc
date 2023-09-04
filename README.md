# Wireguard gRPC Service 

Wireguard gRPC aimed at managing Wireguard configurations. 
The service gives a control over Wireguard setup via gRPC using native client without parsing output of wireguard-tools like `wg` and `wg-quick`.

Client example is at [client/main.go](client/main.go)

# Development

Run the server
```
make cert  # generate localhost certs for mutual authentication (mTLS)
make build  # build a binary
sudo ./wireguard-grpc  # run the server
```

Run the client
```
go run client/main.go
```