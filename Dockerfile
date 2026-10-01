FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /sealcheck ./cmd/sealcheck

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 util-linux && rm -rf /var/lib/apt/lists/*
COPY --from=build /sealcheck /usr/local/bin/sealcheck
COPY lab/entrypoint.sh /usr/local/bin/sealcheck-lab-entrypoint
RUN chmod 0755 /usr/local/bin/sealcheck-lab-entrypoint
USER 10001:10001
ENTRYPOINT ["sealcheck"]
