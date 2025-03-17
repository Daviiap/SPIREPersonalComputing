package attestation

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"net"
	"os"

	"spire-pc/pkg/attestation_module/auth"
	pb "spire-pc/proto/user_attestor"

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedAttestationServiceServer
	token tokenInfo
}

type tokenInfo struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Expiry      string `json:"expiry"`
}

func (s *server) GetUserAttestation(ctx context.Context, in *pb.Empty) (*pb.UserAttestation, error) {
	return &pb.UserAttestation{
		AccessToken: s.token.AccessToken,
		TokenType:   s.token.TokenType,
		Expiry:      s.token.Expiry,
	}, nil
}

func ServeModule(ctx context.Context, auth0Domain, clientID, redirectURI, grpcSocketPath, callBackPort string) {
	if err := os.RemoveAll(grpcSocketPath); err != nil {
		log.Warnf("Failed to remove socket file: %v", err)
	}

	ready := make(chan any)
	go func() {
		lis, err := net.Listen("unix", grpcSocketPath)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}

		token, err := auth.Authenticate(ctx, auth0Domain, clientID, redirectURI, callBackPort)
		if err != nil {
			log.Fatalf("Authentication error: %v", err)
		}

		grpcServer := grpc.NewServer()

		tokenInfostruct := tokenInfo{
			AccessToken: token.AccessToken,
			TokenType:   token.TokenType,
			Expiry:      token.Expiry.Format(time.RFC3339),
		}

		pb.RegisterAttestationServiceServer(grpcServer, &server{
			token: tokenInfostruct,
		})

		go func() {
			<-ctx.Done()
			grpcServer.GracefulStop()
			log.Info("GRPC server stopped")
		}()

		log.Infof("Server listening on unix://%s", grpcSocketPath)
		close(ready)

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-ready
}
