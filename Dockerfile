FROM golang:1.14 AS builder

COPY . /src
WORKDIR /src/cmd/hydroxide
RUN go build -a -tags netgo -installsuffix netgo -ldflags="-s -w -extldflags -static" .

FROM busybox

COPY --from=builder /src/cmd/hydroxide/hydroxide /bin

RUN mkdir -p /etc/ssl/certs && wget https://curl.haxx.se/ca/cacert.pem && mv cacert.pem /etc/ssl/certs

RUN addgroup -S app && adduser -S -G app app 
USER app

ENTRYPOINT ["/bin/hydroxide"]

EXPOSE 1025
EXPOSE 1143
EXPOSE 8080
