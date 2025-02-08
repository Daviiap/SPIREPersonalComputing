BINARY_NAME=user_auth_service
DOCKER_IMAGE=user_auth_service:latest
DIST_DIR=dist

all: build

build: $(DIST_DIR)
	go build -o $(DIST_DIR)/$(BINARY_NAME) main.go

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

run: build
	./$(DIST_DIR)/$(BINARY_NAME)

test:
	go test ./...

clean:
	rm -rf $(DIST_DIR)

docker:
	docker build -t $(DOCKER_IMAGE) .

compose-up:
	docker compose up

compose-up-build:
	docker compose up --build

compose-down:
	docker compose down

create_migration:
	./scripts/create_migration.sh

migrate:
	./scripts/migrate.sh

.PHONY: all build run test clean docker compose-up compose-up-build compose-down create_migration migrate
