package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	pb "spire-pc/proto/user_attestor"

	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
)

type Server struct {
	pb.UnimplementedAttestationServiceServer
	token TokenInfo
}

type x509Watcher struct {
	svidDir string
}

type TokenInfo struct {
	IDToken string `json:"id_token"`
	Expiry  string `json:"expiry"`
}

type Environment struct {
	SPIRESocketPath string
	SVIDDir         string
	GRPCSocketPath  string
	Auth0Domain     string
	ClientID        string
	RedirectURI     string
	CallbackPort    string
}

func (s *Server) GetUserAttestation(ctx context.Context, in *pb.Empty) (*pb.UserAttestation, error) {
	return &pb.UserAttestation{
		AccessToken: s.token.IDToken,
		TokenType:   "id_token",
		Expiry:      s.token.Expiry,
	}, nil
}

func main() {
	env := loadEnvironment()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer handleInterrupt(cancel)

	idToken, expiry, err := authenticateUser(ctx, env)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	if err := startGRPCServerInBackground(ctx, env.GRPCSocketPath, idToken, expiry); err != nil {
		log.Fatalf("gRPC server error: %v", err)
	}

	svidWatcher := x509Watcher{svidDir: env.SVIDDir}
	WatchForSVID(ctx, env.SPIRESocketPath, svidWatcher.svidDir)
}

func loadEnvironment() Environment {
	if err := godotenv.Load(); err != nil {
		log.Warnf("No .env file found, relying on environment variables")
	}

	return Environment{
		SPIRESocketPath: getEnvOrFatal("SPIRE_SOCKET_PATH"),
		SVIDDir:         getEnvOrFatal("SVID_DIR"),
		GRPCSocketPath:  getEnvOrFatal("GRPC_SOCKET_PATH"),
		Auth0Domain:     normalizeAuth0Domain(getEnvOrFatal("AUTH0_DOMAIN")),
		ClientID:        getEnvOrFatal("CLIENT_ID"),
		RedirectURI:     getEnvOrFatal("REDIRECT_URL"),
		CallbackPort:    getEnvOrFatal("CALLBACK_PORT"),
	}
}

func getEnvOrFatal(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("Missing required environment variable: %s", key)
	}
	return val
}

func normalizeAuth0Domain(domain string) string {
	if !strings.HasPrefix(domain, "https://") {
		return "https://" + domain
	}
	return domain
}

func authenticateUser(ctx context.Context, env Environment) (string, time.Time, error) {
	provider, err := oidc.NewProvider(ctx, env.Auth0Domain)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating OIDC provider: %w", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:    env.ClientID,
		RedirectURL: env.RedirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:    provider.Endpoint(),
	}

	authURL := oauth2Config.AuthCodeURL("", oauth2.AccessTypeOffline)
	if err := exec.Command("xdg-open", authURL).Start(); err != nil {
		log.Warnf("Unable to open browser automatically, please visit: %s", authURL)
	}

	return handleAuthCallback(ctx, oauth2Config, env.CallbackPort)
}

func handleAuthCallback(ctx context.Context, oauth2Config oauth2.Config, callbackPort string) (string, time.Time, error) {
	loginCh := make(chan struct {
		idToken string
		expiry  time.Time
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Token exchange error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			http.Error(w, "No ID Token found", http.StatusInternalServerError)
			return
		}

		if err := serveAuthSuccessPage(w); err != nil {
			http.Error(w, "Error serving success page: "+err.Error(), http.StatusInternalServerError)
			return
		}

		loginCh <- struct {
			idToken string
			expiry  time.Time
		}{idToken: rawIDToken, expiry: token.Expiry}
	})

	server := &http.Server{
		Addr:    ":" + callbackPort,
		Handler: mux,
	}

	go func() {
		log.Infof("Starting HTTP callback server on port %s", callbackPort)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	result := <-loginCh

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctxShutdown); err != nil {
		log.Errorf("Error shutting down HTTP server: %v", err)
	}

	return result.idToken, result.expiry, nil
}

func serveAuthSuccessPage(w http.ResponseWriter) error {
	htmlContent, err := os.ReadFile("auth_success.html")
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html")
	_, err = w.Write(htmlContent)
	return err
}

func startGRPCServerInBackground(ctx context.Context, socketPath string, idToken string, expiry time.Time) error {
	removeSocketIfExists(socketPath)

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on socket: %w", err)
	}

	grpcServer := grpc.NewServer()
	tokenInfoStruct := TokenInfo{
		IDToken: idToken,
		Expiry:  expiry.Format(time.RFC3339),
	}
	pb.RegisterAttestationServiceServer(grpcServer, &Server{token: tokenInfoStruct})

	go func() {
		log.Infof("gRPC server listening on %s", socketPath)
		if err := grpcServer.Serve(lis); err != nil {
			log.Errorf("gRPC server error: %v", err)
		}
		log.Infof("gRPC server stopped")
	}()

	go func() {
		<-ctx.Done()
		log.Info("Shutting down gRPC server...")
		grpcServer.GracefulStop()
		lis.Close()
		removeSocketIfExists(socketPath)
	}()

	return nil
}

func removeSocketIfExists(socketPath string) {
	if _, err := os.Stat(socketPath); err == nil {
		if removeErr := os.Remove(socketPath); removeErr != nil {
			log.Errorf("Error removing socket file %s: %v", socketPath, removeErr)
		} else {
			log.Infof("Socket file %s removed", socketPath)
		}
	}
}

func handleInterrupt(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Info("Interrupt signal received, shutting down...")
	cancel()
}

func (watcher *x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for i, svid := range c.SVIDs {
		cert, key, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Infof("SVID updated for %q\n", svid.ID)

		if err := os.WriteFile(fmt.Sprintf("%s/svid%d.crt", watcher.svidDir, i), cert, 0644); err != nil {
			log.Fatalf("Failed to write SVID certificate to file: %v", err)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/svid%d.key", watcher.svidDir, i), key, 0600); err != nil {
			log.Fatalf("Failed to write SVID key to file: %v", err)
		}
	}
}

func (*x509Watcher) OnX509ContextWatchError(err error) {
	log.Errorf("OnX509ContextWatchError error: %v", err)
}

func WatchForSVID(ctx context.Context, spireSocketPath, svidDir string) {
	defer log.Infof("SVID Watcher stopped")
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(spireSocketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	if err := client.WatchX509Context(ctx, &x509Watcher{
		svidDir: svidDir,
	}); err != nil {
		log.Fatalf("Error watching X.509 context: %v", err)
	}
}
