# Makefile

.PHONY: all service clean

all: service

BIN_DIR := bin
SERVICE_BIN := $(BIN_DIR)/service
SERVICE_PKG := ./cmd/service

service: $(SERVICE_BIN)

$(SERVICE_BIN):
	@mkdir -p $(BIN_DIR)
	@echo "Building service -> $(SERVICE_BIN)"
	@go build -o $(SERVICE_BIN) $(SERVICE_PKG)

clean:
	@rm -f $(SERVICE_BIN)
	@echo "cleaned" 
