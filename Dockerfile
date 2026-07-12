# Build stage.
FROM golang:1.26.5 AS build
# Version baked into the binary; the release workflow passes the release tag.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/wgroster ./cmd/wgroster

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wgroster /usr/local/bin/wgroster
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/wgroster", "-config", "/config/config.yaml"]
