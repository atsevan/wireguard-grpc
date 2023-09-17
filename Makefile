export PATH := $(HOME)/go/bin:$(PATH) # TODO: use goenv GOPATH instead of `$HOME/go/`

gen:
	@mkdir -p pb/wg
	protoc --proto_path=proto proto/*.proto --go_out=. --go-grpc_out=.

cert:
	@mkdir -p certs
	# generate server's key and CSR
	openssl req -newkey rsa:2048 -sha256 -nodes -keyout certs/server.key \
		-out certs/server.csr -outform PEM -subj "/CN=localhost" \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

	# generate client's key and CSR
	openssl req -newkey rsa:2048 -sha256 -nodes -keyout certs/client.key \
		-out certs/client.csr -outform PEM -subj "/CN=localhost" \
		-subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"


	# generate CA
	openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
		-nodes -keyout certs/ca.key -out certs/ca.crt -subj "/CN=Root CA"

	# Sign CSRs
	openssl x509 -req \
		-days 365 -sha256 -in certs/server.csr -CA certs/ca.crt \
		-CAkey certs/ca.key -set_serial 1 -out certs/server.crt \
		-copy_extensions copy

	openssl x509 -req \
		-days 365 -sha256 -in certs/client.csr -CA certs/ca.crt \
		-CAkey certs/ca.key -set_serial 2 -out certs/client.crt \
		-copy_extensions copy

clean:
	rm -rf pb; mkdir pb
	rm -rf certs; mkdir certs

run-server:
	go run server/main.go

build-linux:
	GOOS=linux go build -o wireguard-grpc-linux server/main.go

build: tidy
	go build -o wireguard-grpc server/main.go

mac-install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
	brew install protobuf
	brew install clang-format
	brew install grpcurl

linux-install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
	go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

test:
	go test -v -cover -race ./...

tidy:
	go fmt ./...
	go mod tidy -v

docker-build: test
	docker build . --tag wireguard-grpc --tag atsevan/wireguard-grpc

docker-run:
	docker run -it --cap-add=NET_ADMIN docker.io/atsevan/wireguard-grpc --insecure --host 0.0.0.0
