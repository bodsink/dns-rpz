BINARY     = dns-rpz
BUILD_DIR  = bin
SERVER     = root@103.147.52.51
REMOTE_DIR = /opt/dns-rpz

.PHONY: build deploy restart

build:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY) ./cmd/$(BINARY)/

deploy: build
	ssh $(SERVER) "mkdir -p $(REMOTE_DIR)"
	scp $(BUILD_DIR)/$(BINARY) $(SERVER):$(REMOTE_DIR)/$(BINARY).new
	ssh $(SERVER) "mv $(REMOTE_DIR)/$(BINARY).new $(REMOTE_DIR)/$(BINARY)"

restart: deploy
	ssh $(SERVER) "systemctl restart $(BINARY) && sleep 3 && journalctl -u $(BINARY) --no-pager -n 15"
