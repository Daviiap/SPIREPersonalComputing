.PHONY: build proto 

build:
	mkdir -p dist
	go build -o dist/user_attestor_plugin cmd/spire_wl_attestor_plugin/plugin.go
	go build -o dist/attestation_module cmd/attestation_module/attestationModule.go
	go build -o dist/tpm_node_attestor_server cmd/spire_node_attestor_plugin/server/plugin.go
	go build -o dist/tpm_node_attestor_agent cmd/spire_node_attestor_plugin/agent/plugin.go
proto:
	protoc --go_out=. --go-grpc_out=. proto/userAttestation.proto
