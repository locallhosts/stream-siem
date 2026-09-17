# syntax=docker/dockerfile:1
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY go.sum ./
# NOTE: this sandbox's own build had to add `replace` directives in go.mod
# pointing golang.org/x/* and gopkg.in/* vanity imports at their GitHub
# mirrors, because its network egress only allowlists github.com (no Maven
# Central, no module proxy, no golang.org). On a normal machine or CI
# runner with default internet access, GOPROXY=https://proxy.golang.org
# (the Go default) resolves all of these directly and the replace block in
# go.mod is unnecessary — feel free to delete it there. It's kept here so
# `docker build` works unmodified in restricted environments too.
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/forwarder ./cmd/forwarder

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/forwarder /forwarder
ENTRYPOINT ["/forwarder"]
