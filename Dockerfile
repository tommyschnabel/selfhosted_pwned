FROM node:25.1-trixie-slim AS web_build

COPY web /web
WORKDIR /web
RUN npm install && npm run bundle

FROM golang:1.25.4-trixie AS server_build

COPY server /build
WORKDIR /build
RUN go build -o server ./cmd/server/main.go

FROM debian:trixie-slim

COPY --from=web_build /web/dist /dist
COPY --from=server_build /build/server /

RUN apt update && apt install -y ca-certificates

CMD [ "/server" ]
