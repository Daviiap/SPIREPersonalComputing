package domain

import (
	"user_auth_service/utils"

	"github.com/google/uuid"
)

type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
	Password     string
}

func (u *User) GetID() string           { return u.ID }
func (u *User) GetName() string         { return u.Name }
func (u *User) GetEmail() string        { return u.Email }
func (u *User) GetOrganization() string { return u.Organization }
func (u *User) GetPassword() string     { return u.Password }

func (u *User) SetName(name string)   { u.Name = name }
func (u *User) SetEmail(email string) { u.Email = email }
func (u *User) SetOrganization(org string) {
	u.Organization = org
}
func (u *User) SetPassword(password string) {
	passwordHash, err := utils.GeneratePasswordHash(password)
	if err != nil {
		panic(err)
	}
	u.Password = passwordHash
}

func (u *User) IsValidPassword(password string) bool {
	valid, err := utils.VerifyPassword(password, u.Password)
	if err != nil {
		panic(err)
	}
	return valid
}

func NewUser(name, email, organization, password string) *User {
	id := uuid.New().String()

	passwordHash, err := utils.GeneratePasswordHash(password)
	if err != nil {
		panic(err)
	}

	return &User{
		ID:           id,
		Name:         name,
		Email:        email,
		Organization: organization,
		Password:     passwordHash,
	}
}
