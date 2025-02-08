package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	pb "user_attestor_module/proto/user_attestor"

	"google.golang.org/grpc"
)

type LoginRequestBody struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type LoginResponseBody struct {
	Token string `json:"token"`
}

func makeLoginRequest(user, password string) (string, error) {
	url := "http://localhost:3080/login"
	method := "POST"

	payload := LoginRequestBody{
		User:     user,
		Password: password,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(string(payloadBytes)))

	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var loginResponse LoginResponseBody
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return "", err
	}

	return loginResponse.Token, nil
}

type server struct {
	pb.UnimplementedAttestationServiceServer
	Token string
}

func (s *server) GetUserAttestation(ctx context.Context, in *pb.Empty) (*pb.UserAttestation, error) {

	return &pb.UserAttestation{
		UserInfo: &pb.UserInfo{
			Name:         "davi",
			Email:        "davi@email.com",
			Organization: "nuvidio",
		},
	}, nil
}

func getLoginFromTerminal() (string, string, error) {
	var user, password string

	fmt.Print("user: ")
	fmt.Scan(&user)

	fmt.Print("password: ")
	fmt.Print("\033[8m") // Hide input
	fmt.Scan(&password)
	fmt.Print("\033[28m") // Show input

	return user, password, nil
}

func main() {
	user, password, err := getLoginFromTerminal()
	if err != nil {
		log.Fatalf("Failed to get login: %v", err)
	}

	token, err := makeLoginRequest(user, password)
	if err != nil {
		log.Fatalf("Failed to make login request: %v", err)
	}

	const socketPath = "/tmp/user_attestor_module.sock"

	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatalf("Failed to remove socket file: %v", err)
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAttestationServiceServer(grpcServer, &server{Token: token})

	wg := new(sync.WaitGroup)
	wg.Add(1)

	go func() {
		log.Printf("Server listening on unix://%s", socketPath)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
		wg.Done()
	}()

	wg.Wait()
}
