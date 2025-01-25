include .env.test
export

# Default target executed when no arguments are given to make.
_: generate fix lint test cover build up migrate server


generate:
	go generate ./...

SERVER_DIR=./cmd/server
build-server: generate $(SERVER_DIR)/main.go
	go build -buildvcs=false -ldflags "-X main.buildVersion=`git describe --tags 2> /dev/null` -X main.buildDate=`date -u +%Y-%m-%d` -X main.buildCommit=`git rev-parse HEAD`" -o $(SERVER_DIR)/server $(SERVER_DIR) 

build: build-server

.PHONY: server
server: $(SERVER_DIR)/server
	$(SERVER_DIR)/server -d $(DATABASE_DSN)

migrate:
	migrate -source file://migrations -database $(DATABASE_DSN) up

up:
	docker-compose up -d --build

down:
	docker-compose down


fix:
	golangci-lint run --fix

lint:
	golangci-lint run

COVERAGE_PROFILE=reports/profile.cov
test:
	go clean -testcache
	go test -coverprofile=$(COVERAGE_PROFILE) -bench=. -benchmem ./...
	grep -v -E -f .covignore $(COVERAGE_PROFILE) > $(COVERAGE_PROFILE).filtered && mv $(COVERAGE_PROFILE).filtered $(COVERAGE_PROFILE)

cover:
	go tool cover -func=$(COVERAGE_PROFILE) -o reports/coverage.out

docs:
	pkgsite -http=:8080
