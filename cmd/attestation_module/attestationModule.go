package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"spire-pc/pkg/attestation_module/attestation"
)

func WaitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	log.Info("Ctrl+C received, stopping all processes")
	cancel()
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WaitForCtrlC(cancel)

	grpcSocketPath := os.Getenv("GRPC_SOCKET_PATH")
	spireSocketPath := os.Getenv("SPIRE_SOCKET_PATH")
	svidDir := os.Getenv("SVID_DIR")
	auth0Domain := os.Getenv("AUTH0_DOMAIN")
	clientID := os.Getenv("CLIENT_ID")
	redirectURI := os.Getenv("REDIRECT_URL")
	callBackPort := os.Getenv("CALLBACK_PORT")

	attestation.ServeModule(ctx, auth0Domain, clientID, redirectURI, grpcSocketPath, callBackPort)
	attestation.WatchForSVID(ctx, spireSocketPath, svidDir)
}
