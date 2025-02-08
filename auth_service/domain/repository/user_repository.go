package repository

import "user_auth_service/domain"

type UserRepository interface {
	Save(domain.User) error
	Get(string) (domain.User, error)
	GetByName(string) (domain.User, error)
	Delete(domain.User) error
	Update(domain.User) error
}
