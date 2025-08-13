package spirenodeattestorserverplugin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"path"
	"spire-pc/pkg/spire_node_attestor_plugin/common"
	"strings"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func bytesToCert(certBytes []byte) (x509.Certificate, error) {
	block, _ := pem.Decode(certBytes)
	if block != nil {
		certBytes = block.Bytes
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return x509.Certificate{}, fmt.Errorf("error parsing certificate: %w", err)
	}

	return *cert, nil
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

	attestationPayload := common.EkAttestationMsg{}
	if err := json.Unmarshal(payload.GetPayload(), &attestationPayload); err != nil {
		return err
	}

	ekCert, err := bytesToCert(attestationPayload.EkCert)
	if err != nil {
		return err
	}

	ekPub := ekCert.PublicKey

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

	challenge, err := json.Marshal(common.ChallengePayload{
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

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: nonce,
		},
	})
	if err != nil {
		return err
	}

	response, err = stream.Recv()
	if err != nil {
		return err
	}

	platformAttestation := response.GetChallengeResponse()

	var platformInfo attest.PlatformParameters

	decodder := gob.NewDecoder(bytes.NewBuffer(platformAttestation))
	if err := decodder.Decode(&platformInfo); err != nil {
		return err
	}

	pubAk, err := attest.ParseAKPublic(attest.TPMVersion20, params.AK.Public)
	if err != nil {
		log.Fatalf("Failed to parse AK public: %v", err)
	}

	for _, q := range platformInfo.Quotes {
		if err := pubAk.Verify(q, platformInfo.PCRs, nonce); err != nil {
			return err
		}
	}

	eventLog, err := attest.ParseEventLog(platformInfo.EventLog)
	if err != nil {
		return err
	}

	events, err := eventLog.Verify(platformInfo.PCRs)
	if err != nil {
		return err
	}

	selectors, err := buildSelectors(platformInfo, attestationPayload.EkCert, events)
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       AgentID("tpm", config.trustDomain.String(), attestationPayload.EkCert),
				SelectorValues: selectors,
				CanReattest:    true,
			},
		},
	})
}

func buildSelectors(platformInfo attest.PlatformParameters, ek []byte, events []attest.Event) ([]string, error) {
	selectors := []string{}

	selectors = append(selectors, fmt.Sprintf("ek:%x", sha256.Sum256(ek)))

	for _, pcr := range platformInfo.PCRs {
		alg := strings.ReplaceAll(strings.ToLower(pcr.DigestAlg.String()), "-", "")
		selectors = append(selectors, fmt.Sprintf("pcr:%d:%s:%x", pcr.Index, alg, pcr.Digest))
	}

	return selectors, nil
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
