package factory

import (
	"user_auth_service/app/usecases"
	"user_auth_service/domain/repository"
)

type UseCasesFactory struct {
	userRepository *repository.UserRepository
}

func NewUseCasesFactory(userRepository *repository.UserRepository) *UseCasesFactory {
	return &UseCasesFactory{
		userRepository: userRepository,
	}
}

func (f *UseCasesFactory) NewLoginUseCase() usecases.UseCase[usecases.LoginInput, usecases.LoginOutput] {
	return usecases.NewLoginUseCase(f.userRepository)
}

func (f *UseCasesFactory) NewVerifyTokenUseCase() usecases.UseCase[usecases.VerifyTokenInput, usecases.VerifyTokenOutput] {
	return usecases.NewVerifyTokenUseCase(f.userRepository)
}
