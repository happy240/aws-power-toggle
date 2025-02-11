# github.com/gbolo/aws-power-toggle

#
#  BUILD CONTAINERS ------------------------------------------------------------
#

### Building frontend 
#FROM debian:stable as builder-nodejs
FROM node:14.15.1 as builder-nodejs

WORKDIR /app
COPY . .

# install requirements for nvm
#RUN   set -xe; \
#      apt-get update && \
#      apt-get install -y --no-install-recommends ca-certificates curl bash git make

# switch to bash shell and install nvm from official script
SHELL ["/bin/bash", "--login", "-c"]
#RUN   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.37.2/install.sh | bash

# install the correct nodejs version via nvm, then build the frontend
#RUN   nvm install && make frontend
RUN   export PROXY_SOCKS5="socks5://10.20.30.79:10808" && \
      export PROXY_HTTP="http://10.20.30.79:10809" && \
      export http_proxy="http://10.20.30.79:10809" && \
      export HTTP_PROXY="http://10.20.30.79:10809" && \
      export https_proxy="http://10.20.30.79:10809" && \
      export HTTPS_PROXY="http://10.20.30.79:10809" && \
      export all_proxy="http://10.20.30.79:10809" && \
      export ALL_PROXY="http://10.20.30.79:10809"; \
      make frontend


### Building backend
FROM golang:1.14-alpine as builder-golang

WORKDIR /go/src/app
COPY . .

RUN   export PROXY_SOCKS5="socks5://10.20.30.79:10808" && \
      export PROXY_HTTP="http://10.20.30.79:10809" && \
      export http_proxy="http://10.20.30.79:10809" && \
      export HTTP_PROXY="http://10.20.30.79:10809" && \
      export https_proxy="http://10.20.30.79:10809" && \
      export HTTPS_PROXY="http://10.20.30.79:10809" && \
      export all_proxy="http://10.20.30.79:10809" && \
      export ALL_PROXY="http://10.20.30.79:10809"; \
      set -xe; \
      mkdir -p /tmp/build && \
      apk add --no-cache git make && \
      make backend && \
      cp -rp testdata/sampleconfig/power-toggle-config.yaml bin/aws-power-toggle /tmp/build/

#
#  FINAL BASE CONTAINER --------------------------------------------------------
#

#FROM  gbolo/baseos:alpine
FROM  alpine:latest

# prepare env vars
ENV   POWER_TOGGLE_SERVER_STATIC_FILES_DIR /opt/aws-pt/frontend

# prepare homedir
RUN   mkdir -p /opt/aws-pt

# Copy in from builders
COPY  --from=builder-golang /tmp/build/ /opt/aws-pt/
COPY  --from=builder-nodejs /app/frontend/dist /opt/aws-pt/frontend

# Run as non-privileged user by default
USER  65534

# Inherit gbolo/baseos entrypoint and pass it this argument
CMD     ["/opt/aws-pt/aws-power-toggle", "-config", "/opt/aws-pt/power-toggle-config.yaml"]
