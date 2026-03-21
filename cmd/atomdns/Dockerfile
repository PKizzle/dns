ARG DEBIAN_IMAGE=debian:stable-slim
ARG BASE=gcr.io/distroless/static-debian13:nonroot

FROM --platform=$BUILDPLATFORM ${DEBIAN_IMAGE} AS build
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update \
    && apt-get -qq --no-install-recommends install libcap2-bin
COPY atomdns /atomdns
RUN setcap cap_net_bind_service=+ep /atomdns

FROM ${BASE}
COPY --from=build /atomdns /atomdns
USER nonroot:nonroot
WORKDIR /
EXPOSE 53 53/udp
ENTRYPOINT ["/atomdns"]
