FROM alpine as builder
RUN apk add --no-cache go
COPY . /src
WORKDIR /src
RUN CGO_ENABLED=1 CC=gcc go build /src/cmd/hydroxide 
FROM alpine
LABEL version="1.0.0"
LABEL org.opencontainers.image.authors="coding@pierewoehl.de"
LABEL org.opencontainers.image.source = "https://github.com/pierew/hydroxide"
LABEL description="A third-party, open-source ProtonMail bridge. For power users only, designed to run on a server."
COPY --from=builder /src/hydroxide /app/hydroxide
WORKDIR /app
VOLUME [ "/root/.config/hydroxide" ]
CMD ["/app/hydroxide","serve"]
EXPOSE 8080/tcp
EXPOSE 1143/tcp
EXPOSE 1025/tcp
