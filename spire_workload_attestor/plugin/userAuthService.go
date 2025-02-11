package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type ResponseData struct {
	Username     string `json:"username"`
	Email        string `json:"email"`
	Organization string `json:"organization"`
}

type UserAuthService struct {
	serverURL string
}

func NewUserAuthService(serverURL string) *UserAuthService {
	return &UserAuthService{
		serverURL: serverURL,
	}
}

func (uas UserAuthService) GetUserData(token string) (bool, *ResponseData) {
	reqBody, err := json.Marshal(map[string]string{
		"token": token,
	})
	if err != nil {
		return false, nil
	}

	resp, err := http.Post(fmt.Sprintf("%s/verify-token", uas.serverURL), "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	var responseData ResponseData

	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return false, nil
	}

	return true, &responseData
}
