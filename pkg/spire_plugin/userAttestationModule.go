package plugin

import (
	"context"
	"log"
	"time"

	pb "spire-pc/proto/user_attestor"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type UserAttestorModule struct {
	SocketPath string
}

func NewUserAttestorModule(socketPath string) *UserAttestorModule {
	return &UserAttestorModule{
		SocketPath: socketPath,
	}
}

func (uam UserAttestorModule) GetUserAttestationData() (*pb.UserAttestation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		"unix://"+uam.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAttestationServiceClient(conn)

	res, err := client.GetUserAttestation(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("Could not get attestation: %v", err)
	}

	return res, nil
}
