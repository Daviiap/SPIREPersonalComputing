.PHONY: build proto 

build:
	$(MAKE) proto
	mkdir -p dist
	go build -o dist/plugin cmd/spire_plugin/plugin.go
	go build -o dist/attestationModule cmd/attestation_module/attestationModule.go
proto:
	protoc --go_out=. --go-grpc_out=. proto/userAttestation.proto
