# WIP: GCP free-tier instance test
```
echo "Create an GCP instance"
gcloud compute instances create vpn-test-instance-1 \
    --machine-type=e2-micro --zone=us-east1-c --tags wg

echo "Getting a public IP "
PUBLIC_IP=""
while [ -z "${PUBLIC_IP}" ]; do
    echo -n "."
    sleep 3;
    PUBLIC_IP=$(gcloud compute instances describe vpn-test-instance-1  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'  --zone=us-east1-c)
done

echo "\nPublic IP: ${PUBLIC_IP}"

echo "Enable ip_forwarding and setup a wg interface"
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --command='\
        sudo sysctl "net.ipv4.ip_forward=1"; \
        sudo ip link add dev wg0 type wireguard; \
        sudo ip address add 192.168.2.1/24 dev wg0; \
        sudo ip link set mtu 1378 up dev wg0; \
        sudo ip link set up dev wg0; \
        export DEFAULT_DEV=$(ip route | awk "/default/ { print \$5 }"); \
        sudo iptables -t nat -I POSTROUTING 1 -s 192.168.2.0/24 -o ${DEFAULT_DEV} -j MASQUERADE; '

gcloud compute firewall-rules create wg --direction IN --target-tags wg --allow udp:51820 --source-ranges 0.0.0.0/0

# download and run *insecure* wireguard-grpc with port-frowarding to localhost for wireguard-grpc
gcloud compute ssh vpn-test-instance-1 --zone=us-east1-c \
    --ssh-flag="-v" --ssh-flag="-L 8080:localhost:8080" \
    --command="rm -f wireguard-grpc-linux;
        wget https://github.com/atsevan/wireguard-grpc/releases/download/v0.0.1/wireguard-grpc-linux \
        && chmod +x wireguard-grpc-linux \
        && sudo ./wireguard-grpc-linux -insecure"

## open a new terminal
# configure the wireguard device and create a test user
go run client/main.go -configuretest -insecure

# destroy the instance
gcloud compute instances delete vpn-test-instance-1 --zone=us-east1-c --quiet
```