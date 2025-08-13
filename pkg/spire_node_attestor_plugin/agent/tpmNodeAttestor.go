package spirenodeattestoragentplugin

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"spire-pc/pkg/spire_node_attestor_plugin/common"
	"sync"

	"github.com/google/go-attestation/attest"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return err
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		return err
	}
	ek := eks[0]

	akConfig := &attest.AKConfig{}
	ak, err := tpm.NewAK(akConfig)
	if err != nil {
		return err
	}
	defer func() {
		if err := ak.Close(tpm); err != nil {
			p.logger.Error("Error closing AK: %v", err)
		}
	}()
	attestParams := ak.AttestationParameters()

	attestationPayload := common.EkAttestationMsg{
		EkCert: ek.Certificate.Raw,
		AttestationParams: common.AttestationParams{
			Public:                  attestParams.Public,
			UseTCSDActivationFormat: attestParams.UseTCSDActivationFormat,
			CreateData:              attestParams.CreateData,
			CreateAttestation:       attestParams.CreateAttestation,
			CreateSignature:         attestParams.CreateSignature,
		},
	}
	attestationBytes, err := json.Marshal(attestationPayload)
	if err != nil {
		return err
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationBytes,
		},
	})
	if err != nil {
		return err
	}

	challenge, err := stream.Recv()
	if err != nil {
		return err
	}

	challengePayload := common.ChallengePayload{}
	if err := json.Unmarshal(challenge.GetChallenge(), &challengePayload); err != nil {
		return err
	}

	secretClient, err := ak.ActivateCredential(tpm, attest.EncryptedCredential{
		Credential: challengePayload.Credential,
		Secret:     challengePayload.Secret,
	})
	if err != nil {
		return err
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: secretClient,
		},
	})
	if err != nil {
		return err
	}

	challenge, err = stream.Recv()
	if err != nil {
		return err
	}

	nonce := challenge.GetChallenge()

	platformAttestation, err := tpm.AttestPlatform(ak, nonce, &attest.PlatformAttestConfig{})
	if err != nil {
		return err
	}

	var buffer bytes.Buffer
	encodder := gob.NewEncoder(&buffer)
	if err := encodder.Encode(platformAttestation); err != nil {
		return err
	}

	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: buffer.Bytes(),
		},
	})
	if err != nil {
		return err
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
