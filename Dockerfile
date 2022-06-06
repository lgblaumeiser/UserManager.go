FROM golang:1.18-alpine AS build
WORKDIR /go/src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY rest ./rest
COPY service ./service
COPY statik ./statik
COPY store ./store
COPY util ./util
COPY main.go LICENSE entrypoint.sh ./

RUN go build .

FROM alpine:3.16 AS runtime

RUN adduser -D -g '' usermgr

ENV DBHOST=host.docker.internal
ENV DBPORT=5432
ENV DBUSER=postgres
ENV DBPWD=postgres
ENV DBNAME=usermanager

EXPOSE 8080/tcp
USER usermgr

COPY --from=build /go/src/usermanager /go/src/LICENSE /go/src/entrypoint.sh ./

ENTRYPOINT [ "./entrypoint.sh" ]
