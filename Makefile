VGO=go
GOFILES := $(shell find cmd internal -name '*.go' -print)
GOBIN := $(shell $(VGO) env GOPATH)/bin
LINT := $(GOBIN)/golangci-lint
MOCKERY := $(GOBIN)/mockery

# Expect that FireFly compiles with CGO disabled
CGO_ENABLED=0
GOGC=30

.DELETE_ON_ERROR:

all: govulncheck build test go-mod-tidy
# govulncheck
GOVULNCHECK := $(GOBIN)/govulncheck
.PHONY: govulncheck
govulncheck: ${GOVULNCHECK}
	./govulnchecktool.sh
${GOVULNCHECK}:
	${VGO} install golang.org/x/vuln/cmd/govulncheck@latest
test: deps lint
		$(VGO) test ./internal/... ./cmd/... -cover -coverprofile=coverage.txt -covermode=atomic -timeout=30s
coverage.html:
		$(VGO) tool cover -html=coverage.txt
coverage: test coverage.html
lint: ${LINT}
		GOGC=20 $(LINT) run -v --timeout 5m
${MOCKERY}:
		$(VGO) install github.com/vektra/mockery/cmd/mockery@latest
${LINT}:
		$(VGO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest


define makemock
mocks: mocks-$(strip $(1))-$(strip $(2))
mocks-$(strip $(1))-$(strip $(2)): ${MOCKERY}
	${MOCKERY} --case underscore --dir $(1) --name $(2) --outpkg $(3) --output mocks/$(strip $(3))
endef

$(eval $(call makemock, internal/jsonrpc,     WsClient,  jsonrpcmocks))
$(eval $(call makemock, internal/ffcserver,   Server,    ffcservermocks))
$(eval $(call makemock, internal/ffconnector, Connector, ffconnectormocks))

firefly-btcconnect: ${GOFILES}
		$(VGO) build -o ./firefly-btcconnect -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -tags=prod -v ./btcconnect 
go-mod-tidy: .ALWAYS
		$(VGO) mod tidy
build: firefly-btcconnect
.ALWAYS: ;
clean:
		$(VGO) clean
deps:
		$(VGO) get ./btcconnect
reference:
		$(VGO) test ./cmd -timeout=10s -tags docs
docker:
		docker build --build-arg BUILD_VERSION=${BUILD_VERSION} ${DOCKER_ARGS} -t hyperledger/firefly-btcconnect .
