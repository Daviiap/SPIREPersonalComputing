package infra

import (
	"database/sql"
	"user_auth_service/domain"
	repository "user_auth_service/domain/repository"
)

type userRepository struct {
	repository.UserRepository
	db *sql.DB
}

func NewUserRepository(db *sql.DB) repository.UserRepository {
	repo := &userRepository{
		db: db,
	}

	repo.Save(*domain.NewUser("jonh_doe", "john@example.com", "ACME Inc.", "password"))

	return repo
}

func (r *userRepository) Save(user domain.User) error {
	_, err := r.db.Exec(`INSERT INTO users.User (id, name, email, organization, password) VALUES ($1, $2, $3, $4, $5)`,
		user.GetID(), user.GetName(), user.GetEmail(), user.GetOrganization(), user.GetPassword())
	if err != nil {
		return err
	}
	return nil
}

func (r *userRepository) Get(userID string) (domain.User, error) {
	result, err := r.db.Query(`SELECT id, name, email, organization, password FROM users.User WHERE id = $1`, userID)
	if err != nil {
		return domain.User{}, err
	}
	defer result.Close()

	if !result.Next() {
		return domain.User{}, nil
	}

	var user domain.User
	err = result.Scan(&user.ID, &user.Name, &user.Email, &user.Organization, &user.Password)
	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func (r *userRepository) GetByName(userName string) (domain.User, error) {
	result, err := r.db.Query(`SELECT id, name, email, organization, password FROM users.User WHERE name = $1`, userName)
	if err != nil {
		return domain.User{}, err
	}
	defer result.Close()

	if !result.Next() {
		return domain.User{}, nil
	}

	var user domain.User
	err = result.Scan(&user.ID, &user.Name, &user.Email, &user.Organization, &user.Password)
	if err != nil {
		return domain.User{}, err
	}

	return user, nil
}

func (r *userRepository) Delete(user domain.User) error {
	return nil
}

func (r *userRepository) Update(user domain.User) error {
	return nil
}
