package usecases

import (
	"user_auth_service/domain/repository"
	"user_auth_service/utils"
)

type VerifyTokenInput struct {
	Token string `json:"token"`
}

type VerifyTokenOutput struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
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
	userInfo, err := utils.ValidateToken(input.Token)
	if err != nil {
		return VerifyTokenOutput{}, err
	}

	user, err := (*uc.repository).GetByName(userInfo.Name)
	if err != nil || user.GetID() == "" {
		return VerifyTokenOutput{}, err
	}

	return VerifyTokenOutput{
		Username:     user.GetName(),
		Email:        user.GetEmail(),
		Organization: user.GetOrganization(),
	}, nil
}
