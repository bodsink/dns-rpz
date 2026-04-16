BINARY     = dns-rpz
BUILD_DIR  = bin
REMOTE_DIR = /opt/dns-rpz

# Override SERVER di file .deploy.env atau via environment variable:
#   make deploy SERVER=root@your-server-ip
SERVER ?=

-include .deploy.env

.PHONY: build deploy restart

build:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/$(BINARY)/

deploy: build
	@[ -n "$(SERVER)" ] || { echo "ERROR: SERVER tidak diset. Buat file .deploy.env berisi SERVER=root@ip-server atau jalankan: make deploy SERVER=root@ip-server"; exit 1; }
	ssh $(SERVER) "mkdir -p $(REMOTE_DIR)"
	scp $(BUILD_DIR)/$(BINARY) $(SERVER):$(REMOTE_DIR)/$(BINARY).new
	ssh $(SERVER) "mv $(REMOTE_DIR)/$(BINARY).new $(REMOTE_DIR)/$(BINARY)"

restart: deploy
	ssh $(SERVER) "systemctl restart $(BINARY) && sleep 3 && journalctl -u $(BINARY) --no-pager -n 15"
