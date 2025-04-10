package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	UserAttestationServiceURL       string `hcl:"user_attestation_service_url"`
	UserAttestationModuleSocketPath string `hcl:"user_attestation_module_path"`
	Auth0Domain                     string `hcl:"auth0_domain"`
}

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer
	configMtx             sync.RWMutex
	config                *Config
	logger                hclog.Logger
	userAttestationModule *UserAttestorModule
}

type UserInfo struct {
	Sub           string `json:"sub"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Nickname      string `json:"nickname"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	UpdatedAt     string `json:"updated_at"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (p *Plugin) verifyToken(tokenString string) *UserInfo {
	var token oauth2.Token
	err := json.Unmarshal([]byte(tokenString), &token)
	if err != nil {
		fmt.Println("Error unmarshaling token:", err)
	}
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&token))

	req, err := http.NewRequest("GET", p.config.Auth0Domain+"userinfo", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer "+tokenString)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal(err)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Fatal(err)
	}

	return &userInfo
}

func normalizeSelector(input string) string {
	return strings.ReplaceAll(strings.TrimSpace(strings.ToLower(input)), " ", "_")
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		p.logger.Error("Failed to get the configuration", "error", err)
		return nil, err
	}

	userAttestationModule := NewUserAttestorModule(config.UserAttestationModuleSocketPath)
	p.setUserAttestationModule(userAttestationModule)

	attestationData, err := p.userAttestationModule.GetUserAttestationData()
	if err != nil {
		p.logger.Error("Failed to get the user attestation token", "error", err)
		return nil, err
	}

	attestationDataJSON, err := json.Marshal(attestationData)
	if err != nil {
		p.logger.Error("Failed to marshal the user attestation token", "error", err)
		return nil, err
	}
	info := p.verifyToken(string(attestationDataJSON))

	selectors := []string{
		fmt.Sprintf("sub:%s", normalizeSelector(info.Sub)),
		fmt.Sprintf("given_name:%s", normalizeSelector(info.GivenName)),
		fmt.Sprintf("family_name:%s", normalizeSelector(info.FamilyName)),
		fmt.Sprintf("nickname:%s", normalizeSelector(info.Nickname)),
		fmt.Sprintf("name:%s", normalizeSelector(info.Name)),
		fmt.Sprintf("picture:%s", normalizeSelector(info.Picture)),
		fmt.Sprintf("updated_at:%s", normalizeSelector(info.UpdatedAt)),
		fmt.Sprintf("email:%s", normalizeSelector(info.Email)),
		fmt.Sprintf("email_verified:%t", info.EmailVerified),
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectors,
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	if req.HclConfiguration == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration cannot be empty")
	}

	config, err := parseConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}
	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func parseConfig(hclConfig string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, hclConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	return config, nil
}

func (p *Plugin) setUserAttestationModule(userAttestationModule *UserAttestorModule) {
	p.userAttestationModule = userAttestationModule
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.config = config
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
