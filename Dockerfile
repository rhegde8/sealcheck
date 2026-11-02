FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /sealcheck ./cmd/sealcheck

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 util-linux && rm -rf /var/lib/apt/lists/*
COPY --from=build /sealcheck /usr/local/bin/sealcheck
COPY lab/entrypoint.sh /usr/local/bin/sealcheck-lab-entrypoint
RUN chmod 0755 /usr/local/bin/sealcheck-lab-entrypoint
USER 10001:10001
ENTRYPOINT ["sealcheck"]
