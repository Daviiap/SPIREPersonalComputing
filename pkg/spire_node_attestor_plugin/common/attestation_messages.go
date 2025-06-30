package common

type AttestationParams struct {
	Public                  []byte `json:"public"`
	UseTCSDActivationFormat bool   `json:"useTCSDActivationFormat"`
	CreateData              []byte `json:"createData"`
	CreateAttestation       []byte `json:"createAttestation"`
	CreateSignature         []byte `json:"createSignature"`
}

type EkAttestationMsg struct {
	EkCert            []byte            `json:"ekPub"`
	AttestationParams AttestationParams `json:"attestationParams"`
}

type ChallengePayload struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"`
}
