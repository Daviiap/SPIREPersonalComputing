package presentation

import "net/http"

type HttpServer interface {
	AddRoute(route string, handler func(http.ResponseWriter, *http.Request))
	Start()
}
