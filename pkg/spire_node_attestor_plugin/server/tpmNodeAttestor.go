package spirenodeattestorserverplugin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"path"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	trustDomain spiffeid.TrustDomain
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer

	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *Config

	logger hclog.Logger
}

func publicKeyFromBytes(publicKeyBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKeyBytes)
	if block != nil {
		publicKeyBytes = block.Bytes
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	return genericPublicKey, nil
}

type ParsibleAttestationParams struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat"`
	CreateData              []byte `json:"createData"`
	CreateAttestation       []byte `json:"createAttestation"`
	CreateSignature         []byte `json:"createSignature"`
}

type AttestationPayload struct {
	EkPub             []byte                    `json:"ekPub"`
	AttestationParams ParsibleAttestationParams `json:"attestationParams"`
}

type ChallengePayload struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"`
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload, err := stream.Recv()
	if err != nil {
		return err
	}

	attestationPayload := AttestationPayload{}
	if err := json.Unmarshal(payload.GetPayload(), &attestationPayload); err != nil {
		return err
	}

	ekPub, err := publicKeyFromBytes(attestationPayload.EkPub)
	if err != nil {
		return err
	}

	params := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ekPub,
		AK: attest.AttestationParameters{
			Public:                  attestationPayload.AttestationParams.Public,
			UseTCSDActivationFormat: attestationPayload.AttestationParams.UseTCSDActivationFormat,
			CreateData:              attestationPayload.AttestationParams.CreateData,
			CreateAttestation:       attestationPayload.AttestationParams.CreateAttestation,
			CreateSignature:         attestationPayload.AttestationParams.CreateSignature,
		},
	}
	secretServer, encryptedCredentials, err := params.Generate()
	if err != nil {
		return err
	}

	challenge, err := json.Marshal(ChallengePayload{
		Credential: encryptedCredentials.Credential,
		Secret:     encryptedCredentials.Secret,
	})
	if err != nil {
		return err
	}

	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challenge,
		},
	})
	if err != nil {
		return err
	}

	response, err := stream.Recv()
	if err != nil {
		return err
	}

	if !bytes.Equal(response.GetChallengeResponse(), secretServer) {
		return status.Error(codes.Internal, "challenge response does not match")
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       AgentID("tpm", config.trustDomain.String(), attestationPayload.EkPub),
				SelectorValues: []string{"tpm:attested:true"},
				CanReattest:    true,
			},
		},
	})
}

func AgentID(pluginName, trustDomain string, ekPub []byte) string {
	hash := sha256.Sum256(ekPub)

	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path: path.Join(
			"spire",
			"agent",
			pluginName,
			fmt.Sprintf("%x", hash),
		),
	}

	return u.String()
}

func parseCoreConfig(c *configv1.CoreConfiguration) (spiffeid.TrustDomain, error) {
	if c == nil {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "core configuration is missing")
	}

	if c.TrustDomain == "" {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return spiffeid.TrustDomain{}, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	return trustDomain, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	trustDomain, err := parseCoreConfig(req.CoreConfiguration)
	if err != nil {
		return nil, err
	}

	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	config.trustDomain = trustDomain

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}
