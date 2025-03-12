package auth

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"

	"net/http"
	"os"
	"os/exec"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const (
	auth0Domain = "https://dev-j58fwup7mk575dp2.us.auth0.com/"
	clientID    = "4Y91oT15gWZNvij29CTb8WmhPxsSpvbk"
	redirectURI = "http://localhost:3083/"
)

func Authenticate(ctx context.Context) (*oauth2.Token, error) {
	provider, err := oidc.NewProvider(ctx, auth0Domain)
	if err != nil {
		return nil, fmt.Errorf("error creating OIDC provider: %v", err)
	}

	oauth2Config := oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:    provider.Endpoint(),
	}

	authURL := oauth2Config.AuthCodeURL("", oauth2.AccessTypeOnline)
	exec.Command("xdg-open", authURL).Start()

	loginCh := make(chan *oauth2.Token)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Authorization code not found", http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Error exchanging code for token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		htmlContent, err := os.ReadFile("auth_success.html")
		if err != nil {
			http.Error(w, "Error reading HTML file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Write(htmlContent)

		loginCh <- token
	})

	server := http.Server{
		Addr: ":3083",
	}
	go func() {
		log.Info("Starting HTTP server to handle login")
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Error starting HTTP server: %v", err)
		}
		log.Info("HTTP server stopped")
	}()

	token := <-loginCh
	server.Shutdown(ctx)
	return token, nil
}
