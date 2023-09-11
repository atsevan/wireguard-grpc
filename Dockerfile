# syntax=docker/dockerfile:1
FROM golang:1.20-alpine AS build_base

# Set the Current Working Directory inside the container
WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o wireguard-grpc server/main.go

FROM debian:stable-slim

COPY --from=build_base /app/wireguard-grpc /wireguard-grpc

# This container exposes port 8080 to the outside world
EXPOSE 8080

ENTRYPOINT ["/wireguard-grpc"]