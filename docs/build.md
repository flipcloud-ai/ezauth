# Build & Docker

## Prerequisites

- Go >= 1.25
- Docker >= 27 with [BuildKit](https://docs.docker.com/build/buildkit/) enabled
- GNU Make
- (optional) [Helm](https://helm.sh/) >= 3 for chart packaging
- (optional) Google Chrome or Chromium — required for browser-based e2e tests

## Local build

```bash
make build      # build binary → ./ezauth
make test       # run unit + integration tests (ginkgo, excludes e2e)
make test-e2e   # run end-to-end tests (requires Docker + Chrome / Chromium)
make lint       # golangci-lint
make fmt        # gofmt + goimports
```

The binary is built with `-trimpath` and version info injected from git:

```
make build
./ezauth --version
# version: v0.0.1-3-gbf9dc11  commit: bf9dc11  built: 2026-05-13T06:30:00Z
```

## Docker images

Two image targets are provided — pick the right one for your context.

### Development image (`:dev`)

Based on `golang` — includes a shell, debug symbols, and no stripping. Use this for
iterating in a containerised dev environment or debugging with `dlv`.

```bash
make docker-build-dev
```

| Property | Value |
|----------|-------|
| Base image | `golang:1.25` |
| Binary stripped | No |
| Debuggable | Yes |
| Tag | `:dev`, `:<version>-dev` |

### Production image (`:latest`)

Based on `gcr.io/distroless/static:nonroot` — zero shell, zero package manager,
stripped binary. Every `capabilities.drop: ["ALL"]` in the Helm chart is matched
by a minimal container.

```bash
make docker-build
```

| Property | Value |
|----------|-------|
| Base image | `distroless/static:nonroot` |
| Binary stripped | Yes (`-s -w`) |
| Shell | No |
| Tag | `:latest`, `:<version>` |

### Multi-arch production image

Build and push `linux/amd64` + `linux/arm64` in one command using `docker buildx`.

```bash
make docker-buildx
```

Requires a [buildx builder](https://docs.docker.com/build/building/multi-platform/)
with both platforms registered.

### Pushing images

```bash
make docker-push          # push :latest + :<version>
make docker-push-dev      # push :dev + :<version>-dev
```

### Overriding defaults

All build variables are overridable:

```bash
make docker-build \
  DOCKER_REPO=registry.example.com/ezauth \
  VERSION=v0.2.0 \
  PLATFORM=linux/arm64 \
  GO_VERSION=1.26 \
  DISTROLESS_IMAGE=cgr.dev/chainguard/static:latest
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_REPO` | `ghcr.io/flipcloud-ai/ezauth` | Container registry + image name |
| `VERSION` | `git describe --tags --always --dirty` | Image tag and binary version |
| `PLATFORM` | `linux/amd64` | Single-platform target |
| `GO_VERSION` | `1.25` | Go toolchain version for builder |
| `DISTROLESS_IMAGE` | `gcr.io/distroless/static:nonroot` | Production base image |

## End-to-end tests

E2E tests live in `test/e2e/` and exercise a real ezauth server over HTTP.
They require:

- **Docker** — testcontainers-go spins up temporary PostgreSQL containers
- **Chrome / Chromium** — go-rod drives browser-based login and error-page tests

```bash
make test-e2e
```

The CI pipeline runs e2e tests as a separate job (`e2e`) on PRs to
`main`, `develop`, and `release/*` branches.

## Helm chart

```bash
make helm-lint       # lint the chart
make helm-template   # dry-run template rendering
make helm-package    # package → .helm-charts/ezauth-0.1.0.tgz
```

## All Makefile targets

| Target | Description |
|--------|-------------|
| `build` | Compile binary locally |
| `test` | Run unit + integration tests (`ginkgo`, excludes e2e) |
| `test-e2e` | Run end-to-end tests (`ginkgo`, requires Docker + Chrome) |
| `lint` | Run `golangci-lint` |
| `fmt` | Format code (`gofmt` + `goimports`) |
| `dev` | Build + run with `--debug` |
| `docker-build` | Production Docker image |
| `docker-build-dev` | Development Docker image |
| `docker-buildx` | Multi-arch production image + push |
| `docker-push` | Push production images |
| `docker-push-dev` | Push dev images |
| `helm-lint` | Lint Helm chart |
| `helm-template` | Dry-run Helm template |
| `helm-package` | Package Helm chart |
| `service_pb` | Generate protobuf stubs |
