BINARY_NAME=user_auth_service
DOCKER_IMAGE=user_auth_service:latest
DIST_DIR=dist

all: build

build: $(DIST_DIR)
	go build -o $(DIST_DIR)/$(BINARY_NAME) main.go

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

run: build
	./$(DIST_DIR)/$(BINARY_NAME)

test:
	go test ./...

clean:
	rm -rf $(DIST_DIR)

proto:
	protoc --go_out=. --go-grpc_out=. proto/userAttestation.proto

.PHONY: all build run test clean proto
