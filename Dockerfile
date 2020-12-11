FROM golang:1.15-alpine as build
WORKDIR /src

COPY . .
RUN GO111MODULE=on go build ./cmd/hydroxide

#----------------------------------------------------

FROM golang:1.15-alpine
COPY --from=build /src/hydroxide /usr/local/bin

EXPOSE 8080 1025 1143

VOLUME ['/root/.config']
ENTRYPOINT ["/usr/local/bin/hydroxide"]
CMD ["/usr/local/bin/hydroxide", "serve"]