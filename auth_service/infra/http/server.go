package infra

import (
	"net/http"
	"time"
	"user_auth_service/presentation"
)

type Server struct {
	presentation.HttpServer
	server *http.Server
}

func NewServer(port string) presentation.HttpServer {
	return &Server{
		server: &http.Server{
			Addr:              ":" + port,
			ReadHeaderTimeout: time.Second * 10,
		}}
}

func (s *Server) AddRoute(route string, handler func(http.ResponseWriter, *http.Request)) {
	http.HandleFunc(route, handler)
}

func (s *Server) Start() {
	s.server.ListenAndServe()
}
