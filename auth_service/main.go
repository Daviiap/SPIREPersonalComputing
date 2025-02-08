package main

import (
	"log"
	"os"
	"user_auth_service/app/factory"
	infrastructure "user_auth_service/infra"
	infra "user_auth_service/infra/http"
	repository_impl "user_auth_service/infra/repository"
	"user_auth_service/presentation/controller"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load("./.env")
	if err != nil {
		log.Printf("No .env file found, proceeding with system environment variables.")
	}

	db, err := infrastructure.NewDB(os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))
	if err != nil {
		log.Fatal(err)
	}

	userRepository := repository_impl.NewUserRepository(db)
	useCaseFactory := factory.NewUseCasesFactory(&userRepository)

	port := os.Getenv("SERVER_PORT")
	httpServer := infra.NewServer(port)
	controller.NewLoginControllerHttp(&httpServer, useCaseFactory).SetAllRoutes()

	log.Printf("Starting server on port %s", port)
	httpServer.Start()
}
