DOCKER_REPO     ?= ghcr.io/flipcloud-ai/ezauth
DOCKER_DEV_REPO ?= ghcr.io/flipcloud-ai/ezauth-dev
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.1")
GIT_COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DOCKER_BUILDKIT ?= 1
GINKGO_EXTRA_FLAGS ?=
PLATFORM        ?= linux/amd64

GO_VERSION         ?= 1.25
DISTROLESS_IMAGE   ?= gcr.io/distroless/static:nonroot

# ============================================
# Development
# ============================================
.PHONY: dev
dev: build
	./ezauth --debug

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-X 'main.Version=$(VERSION)' -X 'main.GitCommit=$(GIT_COMMIT)' -X 'main.BuildDate=$(BUILD_DATE)'" -o ezauth .

.PHONY: test
test:
	ginkgo -r --procs=4 --timeout=20m --race --trace --skip-package=e2e ./...

.PHONY: test-integration
test-integration:
	ginkgo -r --procs=4 --timeout=20m --race --succinct --silence-skips --skip-package=e2e --tags=integration $(GINKGO_EXTRA_FLAGS) ./...

.PHONY: test-e2e
test-e2e: build
	ginkgo -r --procs=$(if $(EZAUTH_E2E_HOST),1,4) --timeout=20m --race --succinct --silence-skips --tags=e2e ./test/e2e/

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: fmt
fmt:
	gofmt -s -w .
	goimports -w -local github.com/flipcloud-ai/ezauth .

# ============================================
# protobuf
# ============================================
.PHONY: service_pb
service_pb:
	protoc service/proto/node.proto \
	--go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_opt=paths=source_relative

# ============================================
# Docker — development image (golang base, not stripped)
# ============================================
.PHONY: docker-build-dev
docker-build-dev:
	DOCKER_BUILDKIT=$(DOCKER_BUILDKIT) docker build \
		--platform $(PLATFORM) \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg BUILD_FLAGS="-trimpath" \
		--target dev \
		-t $(DOCKER_DEV_REPO):$(VERSION) \
		-t $(DOCKER_DEV_REPO):latest \
		-f Dockerfile .

.PHONY: docker-push-dev
docker-push-dev: docker-build-dev
	docker push $(DOCKER_DEV_REPO):$(VERSION)
	docker push $(DOCKER_DEV_REPO):latest

# ============================================
# Docker — production image (distroless, stripped)
# ============================================
.PHONY: docker-build
docker-build:
	DOCKER_BUILDKIT=$(DOCKER_BUILDKIT) docker build \
		--platform $(PLATFORM) \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg DISTROLESS_IMAGE=$(DISTROLESS_IMAGE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--target production \
		-t $(DOCKER_REPO):$(VERSION) \
		-t $(DOCKER_REPO):latest \
		-f Dockerfile .

.PHONY: docker-push
docker-push: docker-build
	docker push $(DOCKER_REPO):$(VERSION)
	docker push $(DOCKER_REPO):latest

# ============================================
# Docker — multi-arch production (requires buildx)
# ============================================
.PHONY: docker-buildx
docker-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg GO_VERSION=$(GO_VERSION) \
		--build-arg DISTROLESS_IMAGE=$(DISTROLESS_IMAGE) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--target production \
		-t $(DOCKER_REPO):$(VERSION) \
		-t $(DOCKER_REPO):latest \
		--push \
		-f Dockerfile .

# ============================================
# Helm
# ============================================
.PHONY: helm-lint
helm-lint:
	helm lint deployment/charts/ezauth/

.PHONY: helm-template
helm-template:
	helm template test deployment/charts/ezauth/ \
		--set-string secrets.jwtSecret=test-key \
		--set-string secrets.databasePassword=test-db-pass

.PHONY: helm-package
helm-package:
	helm package deployment/charts/ezauth/ -d .helm-charts/
