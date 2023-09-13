# Wireguard gRPC Service 

Wireguard gRPC aimed at managing Wireguard configurations. 
The service gives a control over Wireguard setup via gRPC using native client without parsing output of wireguard-tools like `wg` and `wg-quick`.

Client example is at [client/main.go](client/main.go)

# Run with Docker
## Run
[Note] `docker run` requires NET_ADMIN docker capability

```
$ docker run -it --cap-add=NET_ADMIN -p 8080 docker.io/library/wireguard-grpc --insecure --host 0.0.0.0
```

## Build a docker image
```
$ make build-docker
```

# Build & Run locally

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

## Explore API with `grpcurl`
```
$ grpcurl -plaintext localhost:8080 describe WireGuard
WireGuard is a service:
service WireGuard {
  rpc ConfigureDevice ( .ConfigureDeviceRequest ) returns ( .ConfigureDeviceResponse );
  rpc Device ( .DeviceRequest ) returns ( .DeviceResponse );
  rpc Devices ( .DevicesRequest ) returns ( .DevicesResponse );
}
```

### Configure wireguard device and add a peer
```
$ PEER_KEY=$(wg genkey)
$ grpcurl -plaintext -d @ localhost:8080 WireGuard/ConfigureDevice <<EOM
{
      "name": "wg0",
      "config": {
      "privateKey": "$(wg genkey)",      
      "listenPort": 51820,
      "peers": [
        {
          "publicKey": "$(echo $PEER_KEY | wg pubkey)",
          "persistentKeepaliveInterval": "25s",
          "allowedIps": [
            {
              "ip": "CgcADg==",
              "ipMask": "/////w==" 
            }
          ]
        }
      ]
    }
}
EOM
$ grpcurl -plaintext localhost:8080 WireGuard/Devices

{
  "devices": [
    {
      "name": "wg0",
      "type": "LINUX_KERNEL",
      "privateKey": "iN318Y5xLLLYR4wEMFLfSY+0pOKtJzJLXt3MhoDstV0=",
      "publicKey": "4AmbC1WQtBQ8QCA6NjZrnQZwDAgxq/YCU7fV8/xtVjA=",
      "listenPort": 51820,
      "peers": [
        {
          "publicKey": "4eq4BR7mkU3p6FeaTKnwQ0umJYPW6BvoQhFkjFDONAM=",
          "presharedKey": "iefcb0yW/LDJ0oEqrMHe/sTuGartWok/PEU39RY9Z8A=",
          "persistentKeepaliveInterval": "25s",
          "lastHandshakeTime": "0001-01-01T00:00:00Z",
          "allowedIps": [
            {
              "ip": "CgcADg==",
              "ipMask": "/////w=="
            }
          ],
          "protocolVersion": 1
        }
      ]
    }
  ]
}
```

Convert bytes encoded with base64 to string and vice versa
```
$ python -c "import base64; print(base64.b64encode(bytearray([int(x) for x in '10.7.0.14'.split('.')])))"
b'CgcADg=='
$ python -c "import base64; print('.'.join([str(x) for x in base64.b64decode('CgcADg==')]))"
10.7.0.14
```