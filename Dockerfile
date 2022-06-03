FROM golang:1.17-buster AS builder
ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}
ADD . /btcconnect
WORKDIR /btcconnect
RUN make

FROM debian:buster-slim
WORKDIR /btcconnect
RUN apt update -y \
  && apt install -y curl jq \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /btcconnect/firefly-btcconnect /usr/bin/btcconnect

ENTRYPOINT [ "/usr/bin/btcconnect" ]
