package spirenodeattestoragentplugin

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	TpmPath string `hcl:"tpm_path"`
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer
	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
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

func publicKeyToBytes(pub crypto.PublicKey) ([]byte, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubASN1, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		pubBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubASN1,
		})
		return pubBytes, nil
	case *ecdsa.PublicKey:
		pubASN1, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		pubBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubASN1,
		})
		return pubBytes, nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return status.Error(codes.Internal, "error oppening tpm")
	}

	eks, err := tpm.EKs()
	if err != nil {
		return status.Error(codes.Internal, "error fetching TPM EKs")
	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return status.Error(codes.Internal, "error creating AK")
	}
	attestParams := ak.AttestationParameters()

	akBytes, err := ak.Marshal()
	if err != nil {
		return status.Error(codes.Internal, "error marshaling AK")
	}

	if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
		return status.Error(codes.Internal, "error writing encrypted_aik.json")
	}

	keyBytes, err := publicKeyToBytes(ek.Public)
	if err != nil {
		return status.Error(codes.Internal, "error converting public key to bytes")
	}

	attestationPayload := AttestationPayload{
		EkPub: keyBytes,
		AttestationParams: ParsibleAttestationParams{
			Public:                  attestParams.Public,
			UseTCSDActivationFormat: attestParams.UseTCSDActivationFormat,
			CreateData:              attestParams.CreateData,
			CreateAttestation:       attestParams.CreateAttestation,
			CreateSignature:         attestParams.CreateSignature,
		},
	}
	attestationBytes, err := json.Marshal(attestationPayload)
	if err != nil {
		return status.Error(codes.Internal, "error marshaling attestation payload")
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationBytes,
		},
	})
	if err != nil {
		return status.Error(codes.Internal, "error sending payload")
	}

	challenge, err := stream.Recv()
	if err != nil {
		return status.Error(codes.Internal, "error receiving challenge")
	}

	challengePayload := ChallengePayload{}
	if err := json.Unmarshal(challenge.GetChallenge(), &challengePayload); err != nil {
		return status.Error(codes.Internal, "error unmarshaling challenge payload")
	}

	akBytes, err = os.ReadFile("encrypted_aik.json")
	if err != nil {
		return status.Error(codes.Internal, "error reading encrypted_aik.json")
	}
	ak, err = tpm.LoadAK(akBytes)
	if err != nil {
		return status.Error(codes.Internal, "error loading AK")
	}
	secretClient, err := ak.ActivateCredential(tpm, attest.EncryptedCredential{
		Credential: challengePayload.Credential,
		Secret:     challengePayload.Secret,
	})
	if err != nil {
		return status.Error(codes.Internal, "error activating credential")
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: secretClient,
		},
	})
	if err != nil {
		return status.Error(codes.Internal, "error sending challenge response")
	}

	return nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	if config.TpmPath == "" {
		config.TpmPath = "/dev/tpm0"
	}

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
