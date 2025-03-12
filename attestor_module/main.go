package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	pb "user_attestor_module/proto/user_attestor"

	"github.com/joho/godotenv"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	spireSocketPath = "unix:///tmp/spire-agent/public/api.sock"
	grpcSocketPath  = "/tmp/user_attestor_module.sock"
	svidDir         = "/home/davi/UFCG/SPIREPersonalComputing/attestor_module"
)

type LoginRequestBody struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type LoginResponseBody struct {
	Token string `json:"token"`
}

func makeLoginRequest(user, password string) (string, error) {
	err := godotenv.Load("./.env")
	if err != nil {
		log.Println("No .env file found, proceeding with system environment variables.")
	}
	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		return "", fmt.Errorf("AUTH_SERVICE_URL environment variable is not set")
	}
	log.Printf("Using AUTH_SERVICE_URL: %s", authServiceURL)

	payloadBytes, err := json.Marshal(LoginRequestBody{User: user, Password: password})
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", authServiceURL+"/login", strings.NewReader(string(payloadBytes)))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var loginResponse LoginResponseBody
	if err := json.Unmarshal(body, &loginResponse); err != nil {
		return "", err
	}

	return loginResponse.Token, nil
}

type server struct {
	pb.UnimplementedAttestationServiceServer
	Token string
}

func (s *server) GetUserAttestation(ctx context.Context, in *pb.Empty) (*pb.UserAttestation, error) {
	return &pb.UserAttestation{AttestationToken: s.Token}, nil
}

func getLoginFromTerminal() (string, string, error) {
	fmt.Print("user: ")
	var user string
	fmt.Scan(&user)

	fmt.Print("password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", "", err
	}

	return user, string(bytePassword), nil
}

type x509Watcher struct{}

func (x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for i, svid := range c.SVIDs {
		cert, key, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Printf("SVID updated for %q\n", svid.ID)

		if err := os.WriteFile(fmt.Sprintf("%s/svids/svid%d.crt", svidDir, i), cert, 0644); err != nil {
			log.Fatalf("Failed to write SVID certificate to file: %v", err)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/svids/svid%d.key", svidDir, i), key, 0600); err != nil {
			log.Fatalf("Failed to write SVID key to file: %v", err)
		}
	}
}

func (x509Watcher) OnX509ContextWatchError(err error) {
	if status.Code(err) != codes.Canceled {
		log.Printf("OnX509ContextWatchError error: %v", err)
	}
}

func executeModule(ctx context.Context, token string) {
	if err := os.RemoveAll(grpcSocketPath); err != nil {
		log.Printf("Warning: Failed to remove socket file: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		lis, err := net.Listen("unix", grpcSocketPath)
		if err != nil {
			log.Fatalf("Failed to listen: %v", err)
		}

		grpcServer := grpc.NewServer()
		pb.RegisterAttestationServiceServer(grpcServer, &server{Token: token})

		go func() {
			<-ctx.Done()
			grpcServer.GracefulStop()
			log.Println("GRPC server stopped")
		}()

		log.Printf("Server listening on unix://%s", grpcSocketPath)
		close(ready)

		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-ready

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(spireSocketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	if err := client.WatchX509Context(ctx, &x509Watcher{}); err != nil && status.Code(err) != codes.Canceled {
		log.Fatalf("Error watching X.509 context: %v", err)
	}
}

func waitForCtrlC(cancel context.CancelFunc) {
	log.Println("Waiting for Ctrl+C...")
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	log.Println("Ctrl+C received, cancelling...")
	cancel()
}

func main() {
	user, password, err := getLoginFromTerminal()
	if err != nil {
		log.Fatalf("Failed to get login: %v", err)
	}

	token, err := makeLoginRequest(user, password)
	if err != nil {
		log.Fatalf("Failed to make login request: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go waitForCtrlC(cancel)
	executeModule(ctx, token)
}
