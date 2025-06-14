FROM node:21 AS node_build

WORKDIR /go/src/github.com/siyuan-note/siyuan/
ADD . /go/src/github.com/siyuan-note/siyuan/
RUN apt-get update && \
    apt-get install -y jq
RUN cd app && \
packageManager=$(jq -r '.packageManager' package.json) && \
if [ -n "$packageManager" ]; then \
    npm install -g $packageManager; \
else \
    echo "No packageManager field found in package.json"; \
    npm install -g pnpm; \
fi && \
pnpm install --registry=http://registry.npmjs.org/ --silent && \
pnpm run build
RUN apt-get purge -y jq
RUN apt-get autoremove -y
RUN rm -rf /var/lib/apt/lists/*

FROM golang:1.24-alpine AS go_build
WORKDIR /go/src/github.com/siyuan-note/siyuan/
COPY --from=node_build /go/src/github.com/siyuan-note/siyuan/ /go/src/github.com/siyuan-note/siyuan/
ENV GO111MODULE=on
ENV CGO_ENABLED=1
RUN apk add --no-cache gcc musl-dev && \
    cd kernel && go build --tags fts5 -v -ldflags "-s -w" && \
    mkdir /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/app/appearance/ /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/app/stage/ /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/app/guide/ /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/app/changelogs/ /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/kernel/kernel /opt/siyuan/ && \
    mv /go/src/github.com/siyuan-note/siyuan/kernel/entrypoint.sh /opt/siyuan/entrypoint.sh && \
    find /opt/siyuan/ -name .git | xargs rm -rf

FROM alpine:latest
LABEL org.opencontainers.image.source="https://github.com/Ran-snow/siyuan"
LABEL org.opencontainers.image.description="Some free change base on siyuan-note/siyuan"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

WORKDIR /opt/siyuan/
COPY --from=go_build /opt/siyuan/ /opt/siyuan/

RUN apk add --no-cache ca-certificates tzdata su-exec && \
    chmod +x /opt/siyuan/entrypoint.sh

ENV TZ=Asia/Shanghai
ENV HOME=/home/siyuan
ENV RUN_IN_CONTAINER=true
EXPOSE 6806

ENTRYPOINT ["/opt/siyuan/entrypoint.sh"]
CMD ["/opt/siyuan/kernel"]
