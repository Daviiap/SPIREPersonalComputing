FROM golang:1.23.3-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o user_auth_service main.go

FROM alpine:latest

LABEL developers="Davi <davi.pontes@ccc.ufcg.edu.br>"

WORKDIR /app

COPY --from=builder /app/user_auth_service .

CMD ["./user_auth_service"]
