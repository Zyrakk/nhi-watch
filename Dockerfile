# Build stage
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
      -X github.com/Zyrakk/nhi-watch/internal/cli.Version=${VERSION} \
      -X github.com/Zyrakk/nhi-watch/internal/cli.Commit=${COMMIT} \
      -X github.com/Zyrakk/nhi-watch/internal/cli.BuildDate=${BUILD_DATE}" \
    -o /nhi-watch ./cmd/nhi-watch

# Final stage — distroless for minimal attack surface
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /nhi-watch /nhi-watch
USER 65534
ENTRYPOINT ["/nhi-watch"]
