export PATH := $(HOME)/go/bin:$(PATH) # TODO: use goenv GOPATH instead of `$HOME/go/`

gen:
	protoc --proto_path=proto proto/*.proto --go_out=. --go-grpc_out=.

clean:
	rm -rf pb/

run-server:
	go run server/main.go

build-linux:
	GOOS=linux GOARCH=amd64 go build  -o wireguard-grpc-linux server/main.go

build-mac:
	GOOS=darwin GOARCH=amd64 go build  -o wireguard-grpc-darwin server/main.go

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