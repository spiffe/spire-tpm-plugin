FROM --platform=${BUILDPLATFORM} golang:1.24.0-alpine3.20 as build

ARG BINARY
ARG TARGETOS
ARG TARGETARCH

ENV binary_env=$binary

RUN apk --no-cache add make && \
    mkdir /app

WORKDIR /app
COPY . .

RUN TARGETOS=${TARGETOS} TARGETARCH=${TARGETARCH} BINARY=${BINARY} make docker-build

FROM --platform=${TARGETPLATFORM} alpine:3.17

WORKDIR /app

ARG BINARY
ENV BINARY_ENV=${BINARY}

COPY --from=build /app/${BINARY_ENV} ./${BINARY_ENV}

ENTRYPOINT ./${BINARY_ENV}
