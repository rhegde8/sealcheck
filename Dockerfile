FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
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
