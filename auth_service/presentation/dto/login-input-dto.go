package dto

type LoginInput struct {
	User     string `json:"user"`
	Password string `json:"password"`
}
