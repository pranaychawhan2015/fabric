# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

ARG GO_VER
ARG ALPINE_VER
FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang

RUN apk add --no-cache \
	bash \
	binutils-gold \
	gcc \
	git \
	make \
	musl-dev;

ADD . /home/cps16/go/src/fabric
WORKDIR /home/cps16/go/src/fabric

FROM golang as tools
ARG GO_TAGS
RUN make tools GO_TAGS=${GO_TAGS}

FROM golang:${GO_VER}-alpine${ALPINE_VER}
# git is required to support `go list -m`
RUN apk add --no-cache \
	bash \
	git \
	jq \
	tzdata;
ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
VOLUME /etc/hyperledger/fabric
COPY --from=tools /home/cps16/go/src/fabric/build/bin /usr/local/bin
COPY --from=tools /home/cps16/go/src/fabric/sampleconfig ${FABRIC_CFG_PATH}
