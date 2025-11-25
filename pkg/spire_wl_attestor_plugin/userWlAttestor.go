package plugin

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	pb "spire-pc/proto/user_attestor"
	"strings"
	"sync"

	"github.com/coreos/go-oidc"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func GetUserAttestationData(ctx context.Context, socketPath string) (*pb.UserAttestation, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewAttestationServiceClient(conn)

	resp, err := client.GetUserAttestation(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("Error calling GetUserAttestation: %v", err)
	}
	return resp, nil
}

type Config struct {
	Auth0Domain string `hcl:"auth0_domain"`
	ClientID    string `hcl:"client_id"`
	SocketPath  string `hcl:"socket_path"`
}

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
}

type UserInfo struct {
	Sub           string `json:"sub"`
	Nickname      string `json:"nickname"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (p *Plugin) verifyToken(ctx context.Context, idToken string) (*UserInfo, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration: %w", err)
	}

	// ===== Verify ID Token =====
	provider, err := oidc.NewProvider(ctx, normalizeAuth0Domain(config.Auth0Domain))
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	token, err := verifier.Verify(ctx, idToken)
	if err != nil {
		log.Fatalf("ID Token verification failed: %v", err)
	}

	var userInfo UserInfo
	if err := token.Claims(&userInfo); err != nil {
		log.Fatalf("Failed to parse claims into UserInfo: %v", err)
	}

	return &userInfo, nil
}

func (p *Plugin) getSocketInodes(pid string) (map[string]struct{}, error) {
	fdDir := filepath.Join("/proc", pid, "fd")
	fdEntries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", fdDir, err)
	}

	inodes := map[string]struct{}{}
	for _, entry := range fdEntries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") {
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			inodes[inode] = struct{}{}
		}
	}
	return inodes, nil
}

func (p *Plugin) findSocketPathByInodes(inodes map[string]struct{}) (string, error) {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return "", fmt.Errorf("failed to open /proc/net/unix: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 7 {
			inode := fields[6]
			if _, ok := inodes[inode]; ok && len(fields) >= 8 {
				return fields[7], nil
			}
		}
	}
	return "", nil
}

func (p *Plugin) getSocketPath(pid string) (string, error) {
	inodes, err := p.getSocketInodes(pid)
	if err != nil {
		return "", err
	}
	return p.findSocketPathByInodes(inodes)
}

func normalizeAuth0Domain(domain string) string {
	result := domain

	if !strings.HasPrefix(domain, "https://") {
		result = "https://" + result
	}

	if !strings.HasSuffix(domain, "/") {
		result = result + "/"
	}

	return result
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	socketPath, err := p.getSocketPath(fmt.Sprintf("%d", req.Pid))
	if err != nil || socketPath == "" {
		return nil, status.Error(codes.FailedPrecondition, "no user attestation module socket path found")
	}

	if socketPath != p.config.SocketPath {
		return nil, nil
	}

	attestationData, err := GetUserAttestationData(ctx, socketPath)
	if err != nil {
		p.logger.Error("Failed to get user attestation token", "error", err)
		return nil, err
	}

	info, err := p.verifyToken(ctx, attestationData.AccessToken)
	if err != nil {
		p.logger.Error("Failed to verify token", "error", err)
		return nil, err
	}

	selectors := []string{
		fmt.Sprintf("sub:%s", normalizeSelector(info.Sub)),
		fmt.Sprintf("nickname:%s", normalizeSelector(info.Nickname)),
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

func parseConfig(hclConfig string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, hclConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	return config, nil
}

func normalizeSelector(input string) string {
	return strings.ReplaceAll(strings.TrimSpace(strings.ToLower(input)), " ", "_")
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
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
