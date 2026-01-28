# Makefile

.PHONY: all service clean windows

all: service

BIN_DIR := bin
SERVICE_BIN := $(BIN_DIR)/service
SERVICE_PKG := ./cmd/service

# Windows build output
SERVICE_BIN_WINDOWS := $(BIN_DIR)/service-windows.exe

service: $(SERVICE_BIN)

$(SERVICE_BIN):
	@mkdir -p $(BIN_DIR)
	@echo "Building service -> $(SERVICE_BIN)"
	@go build -o $(SERVICE_BIN) $(SERVICE_PKG)

windows: $(SERVICE_BIN_WINDOWS)

$(SERVICE_BIN_WINDOWS):
	@mkdir -p $(BIN_DIR)
	@echo "Building service for Windows -> $(SERVICE_BIN_WINDOWS)"
	@env GOOS=windows GOARCH=amd64 go build -o $(SERVICE_BIN_WINDOWS) $(SERVICE_PKG)

clean:
	@rm -f $(SERVICE_BIN)
	@echo "cleaned"
