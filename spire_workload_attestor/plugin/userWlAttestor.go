package plugin

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	UserAttestationServiceURL       string `hcl:"user_attestation_service_url"`
	UserAttestationModuleSocketPath string `hcl:"user_attestation_module_path"`
}

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer
	configMtx             sync.RWMutex
	config                *Config
	logger                hclog.Logger
	userAttestationModule *UserAttestorModule
	userAuthService       *UserAuthService
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		p.logger.Error("Failed to get the configuration", "error", err)
		return nil, err
	}

	userAttestationModule := NewUserAttestorModule(config.UserAttestationModuleSocketPath)
	p.setUserAttestationModule(userAttestationModule)

	userAttestationToken, err := p.userAttestationModule.GetUserAttestationData()
	if err != nil {
		p.logger.Error("Failed to get the user attestation token", "error", err)
		return nil, err
	}

	userAuthService := NewUserAuthService(config.UserAttestationServiceURL)
	p.setUserAuthService(userAuthService)

	isValid, userData := userAuthService.GetUserData(userAttestationToken.AttestationToken)
	if !isValid {
		p.logger.Error("Failed to get the user data", "error", err)
		return nil, err
	}

	selectors, err := p.buildSelectors(userData)
	if err != nil {
		p.logger.Error("Failed to build selectors", "error", err)
		return nil, err
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

func (p *Plugin) setUserAuthService(userAuthService *UserAuthService) {
	p.userAuthService = userAuthService
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

func (p *Plugin) buildSelectors(userInfo *ResponseData) ([]string, error) {
	selectors := []string{}

	selectors = append(selectors, "name:"+strings.ToLower(strings.Replace(userInfo.Username, " ", "_", -1)))
	selectors = append(selectors, "email:"+strings.ToLower(strings.Replace(userInfo.Email, " ", "_", -1)))
	selectors = append(selectors, "organization:"+strings.ToLower(strings.Replace(userInfo.Organization, " ", "_", -1)))

	return selectors, nil
}
