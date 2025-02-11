package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"user_auth_service/app/factory"
	"user_auth_service/app/usecases"
	"user_auth_service/presentation"
	"user_auth_service/presentation/dto"
)

type LoginControllerHttp struct {
	HttpController
	httpServer      *presentation.HttpServer
	useCasesFactory *factory.UseCasesFactory
}

func NewLoginControllerHttp(httpServer *presentation.HttpServer, useCasesFactory *factory.UseCasesFactory) HttpController {
	return &LoginControllerHttp{
		httpServer:      httpServer,
		useCasesFactory: useCasesFactory,
	}
}

func (c *LoginControllerHttp) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var request dto.LoginInput

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	output, err := c.useCasesFactory.NewLoginUseCase().Execute(usecases.LoginInput{
		User:     request.User,
		Password: request.Password,
	})

	if err != nil {
		http.Error(w, "Error validating token", http.StatusInternalServerError)
		return
	}

	if output.Token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(json.RawMessage(`{"message": "Invalid credentials"}`))
		return
	}

	if err := json.NewEncoder(w).Encode(output); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

func (c *LoginControllerHttp) verifyToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var request dto.VerifyTokenInput

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Printf("Error decoding request: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	output, err := c.useCasesFactory.NewVerifyTokenUseCase().Execute(usecases.VerifyTokenInput{
		Token: request.Token,
	})

	if err != nil {
		http.Error(w, "Error validating token", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(output); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

func (c *LoginControllerHttp) SetAllRoutes() {
	(*c.httpServer).AddRoute(
		"/login",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				c.login(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		},
	)

	(*c.httpServer).AddRoute(
		"/verify-token",
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				c.verifyToken(w, r)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
		},
	)
}
