
FROM golang:1.15.6 AS build
#1.15.5-alpine3.12
# docker run -e USERNAME -e PASSWORD -e TOKEN= hydr:latest
# docker run -it hydr:latest

ADD . /src
WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hydroxide ./cmd/hydroxide

FROM alpine:3.12.2 as final

WORKDIR /hydroxide
COPY --from=build /src/hydroxide .
COPY entrypoint.sh .

# SMTP IMAP CalDAV
EXPOSE 1025 1143 8080

CMD [ "/bin/sh", "-c", "/hydroxide/entrypoint.sh" ]
# ENTRYPOINT [ "/hydroxide/entrypoint.sh" ]