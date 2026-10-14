# EatAll — POC 吸收系统
# 目标: 构建 Go 代理 / 生成证书 / 测试 / 运行

GO      := go
BIN     := bin/eatal-proxy
DEVCFG  := config/config.dev.yaml

.PHONY: all build cert test run dev test-py clean

all: build

build:
	$(GO) build -o $(BIN) ./cmd/proxy

cert:
	$(GO) run scripts/gen-cert.go

test:
	$(GO) test ./...

test-py:
	cd pipeline && python -m pytest tests/ -q

run:
	$(GO) run ./cmd/proxy -config $(DEVCFG)

dev: build cert
	$(BIN) -config $(DEVCFG)

clean:
	rm -rf bin data/sessions
