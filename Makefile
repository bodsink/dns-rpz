BINARY_DNS  = dns-rpz-dns
BINARY_HTTP = dns-rpz-dashboard
BUILD_DIR   = bin
REMOTE_DIR  = /opt/dns-rpz
SYSTEMD     = /etc/systemd/system

# Override SERVER di file .deploy.env atau via environment variable:
#   make deploy SERVER=root@your-server-ip
SERVER ?=

-include .deploy.env

.PHONY: build deploy install-services restart restart-dns restart-http

build:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_DNS) ./cmd/dns-rpz/
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_HTTP) ./cmd/dns-rpz-dashboard/

deploy: build
	@[ -n "$(SERVER)" ] || { echo "ERROR: SERVER tidak diset. Buat file .deploy.env berisi SERVER=root@ip-server atau jalankan: make deploy SERVER=root@ip-server"; exit 1; }
	ssh $(SERVER) "mkdir -p $(REMOTE_DIR)"
	scp $(BUILD_DIR)/$(BINARY_DNS) $(SERVER):$(REMOTE_DIR)/$(BINARY_DNS).new
	ssh $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_DNS).new $(REMOTE_DIR)/$(BINARY_DNS)"
	scp $(BUILD_DIR)/$(BINARY_HTTP) $(SERVER):$(REMOTE_DIR)/$(BINARY_HTTP).new
	ssh $(SERVER) "mv $(REMOTE_DIR)/$(BINARY_HTTP).new $(REMOTE_DIR)/$(BINARY_HTTP)"
	scp -r assets $(SERVER):$(REMOTE_DIR)/

# Install/update kedua systemd service file lalu reload daemon.
# Jalankan sekali setelah pertama kali setup, atau saat service file berubah.
install-services:
	@[ -n "$(SERVER)" ] || { echo "ERROR: SERVER tidak diset."; exit 1; }
	scp systemctl/dns-rpz-dns.service $(SERVER):$(SYSTEMD)/dns-rpz-dns.service
	scp systemctl/dns-rpz-http.service $(SERVER):$(SYSTEMD)/dns-rpz-http.service
	ssh $(SERVER) "systemctl daemon-reload && systemctl enable dns-rpz-dns dns-rpz-http"
	@echo "Service files installed. Jalankan 'make restart' untuk memulai ulang."

# Restart kedua service sekaligus (deploy dulu).
restart: deploy
	ssh $(SERVER) "systemctl restart dns-rpz-dns dns-rpz-http && sleep 5 && journalctl -u dns-rpz-dns -u dns-rpz-http --no-pager -n 20"

# Restart hanya DNS service (tanpa downtime dashboard).
restart-dns: deploy
	ssh $(SERVER) "systemctl restart dns-rpz-dns && sleep 3 && journalctl -u dns-rpz-dns --no-pager -n 10"

# Restart hanya HTTP dashboard (tanpa mengganggu DNS).
restart-http: deploy
	ssh $(SERVER) "systemctl restart dns-rpz-http && sleep 2 && journalctl -u dns-rpz-http --no-pager -n 10"
