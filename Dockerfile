
# The intention was to stop pulling all these module dependencies every build but Docker doesn't seem to be able to help itself from rebuilding this first stage. May be something I can do in the command line at build time to suggest the local image copy of the finished stage.
FROM golang:1.15.5-alpine3.12 AS dependencies

ADD . /src
WORKDIR /src
RUN go get ./cmd/hydroxide

FROM golang:1.15.5-alpine3.12 AS compilation

COPY --from=dependencies /go /go
ADD . /src
WORKDIR /src

# The Go111Module flag doesn't appear to be necessary. Could also separate out the other flags for legibility.
ENV GO111MODULE=on
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hydroxide ./cmd/hydroxide

FROM alpine:3.12.2 as run

LABEL org.opencontainers.image.title="Hydroxide"
LABEL org.opencontainers.image.description="Containerised version of Hydroxide, the FOSS alternative to ProtonMail's Bridge application. Authenticates and exposes SMTP, IMAP, and CalDAV interfaces."
LABEL org.opencontainers.image.version="0.2.16"
LABEL org.opencontainers.image.authors="Ariel@Richtman.com.au;"
LABEL org.opencontainers.image.source="https://github.com/arichtman/hydroxide"

#TODO: Consider if it's wise to store this. Without token expiry this is pretty dangerous as it negates the security of two factor authentication. I've not checked if it's even possible to explicitly revoke an access token. OTOH it'll make container restarts more reliable as they'll be guaranteed a working access token (more of a concern on kubernetes where restarted pods might be scheduled to a different node)
VOLUME [ "~/.config/hydroxide" ]

WORKDIR /hydroxide
COPY --from=compilation /src/hydroxide .
# NB: Ensure execute permissions on source file or add a RUN chmod step (more wasteful)
COPY entrypoint.sh .

# SMTP IMAP CalDAV
EXPOSE 1025 1143 8080

# This is some nonsense due to variable substitution and executing commands without shell sessions
ENTRYPOINT [ "/bin/sh", "-c", "/hydroxide/entrypoint.sh ${USERNAME} ${PASSWORD} ${TOKEN}" ]
