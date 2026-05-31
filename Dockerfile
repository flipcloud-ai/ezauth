# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25
ARG DISTROLESS_IMAGE=gcr.io/distroless/static:nonroot

# ============================================
# Stage: builder
# ============================================
FROM golang:${GO_VERSION} AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG BUILD_FLAGS="-trimpath -ldflags=-s -w"
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    go build ${BUILD_FLAGS} \
    -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.GitCommit=${GIT_COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" \
    -o ezauth .

# ============================================
# Stage: dev (debuggable binary, shell available)
# ============================================
FROM golang:${GO_VERSION} AS dev

COPY --from=builder /src/ezauth /ezauth
EXPOSE 8088
ENTRYPOINT ["/ezauth"]

# ============================================
# Stage: production (distroless, minimal attack surface)
# ============================================
FROM ${DISTROLESS_IMAGE} AS production

COPY --from=builder /src/ezauth /ezauth
EXPOSE 8088
ENTRYPOINT ["/ezauth"]
