# WIP: GCP free-tier instance test
```
# create an instance
gcloud compute instances create vpn-test-instance-1 --machine-type=e2-micro --zone=us-east1-c 

# enable ip_forwarding and setup a wg interface
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --command="\
        sudo sysctl 'net.ipv4.ip_forward=1'; \
        sudo ip link add dev wg0 type wireguard; \
        sudo ip address add 192.168.2.1/24 dev wg0; \
        sudo ip link set up dev wg0;"

# download and run *insecure* wireguard-grpc with port-frowarding to localhost for grpc and Wireguard
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --ssh-flag="-v" --ssh-flag="-L 8080:localhost:8080" --ssh-flag="-L 51820:localhost:51820" \
    --command="rm -f wireguard-grpc-linux;
        wget https://github.com/atsevan/wireguard-grpc/releases/download/v0.0.1/wireguard-grpc-linux \
        && chmod +x wireguard-grpc-linux \
        && sudo ./wireguard-grpc-linux -insecure"

## open a new terminal
# configure the wireguard device and create a test user
go run client/main.go -configuredevice -insecure

# destroy the instance
gcloud compute instances delete vpn-test-instance-1 --zone=us-east1-c --quiet
```