package usecases

import (
	"user_auth_service/domain/repository"
)

type VerifyTokenInput struct {
	Token string `json:"token"`
}

type VerifyTokenOutput struct {
	Token string `json:"token"`
}

type VerifyTokenUseCase struct {
	UseCase[VerifyTokenInput, VerifyTokenOutput]
	repository *repository.UserRepository
}

func NewVerifyTokenUseCase(repository *repository.UserRepository) UseCase[VerifyTokenInput, VerifyTokenOutput] {
	return &VerifyTokenUseCase{
		repository: repository,
	}
}

func (uc *VerifyTokenUseCase) Execute(input VerifyTokenInput) (VerifyTokenOutput, error) {
	return VerifyTokenOutput{Token: input.Token}, nil
}
