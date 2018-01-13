# hydroxide

A third-party, open-source ProtonMail bridge. For power users only, designed to
run on a server.

hydroxide supports CardDAV, IMAP and SMTP.

Rationale:

* No GUI, only a CLI (so it runs in headless environments)
* Standard-compliant (we don't care about Microsoft Outlook)
* Fully open-source

## Setup

### Go

hydroxide is implemented with Go. Head to [Go website](https://golang.org)
for setup information.

### Install and Setup

Install hydroxide

```shell
go get github.com/emersion/hydroxide/cmd/hydroxide
```

Your credentials will be stored on disk encrypted with a 32-byte random
password. When configuring your client, you'll need this password.

```shell
hydroxide auth <username>
```

## Usage

hydroxide can be used in multiple modes.

### CardDAV

You must setup an HTTPS reverse proxy to forward requests to `hydroxide`.

```shell
hydroxide carddav
```

Tested on GNOME (Evolution) and Android (DAVDroid).

### IMAP

For now, it only supports unencrypted local connections.

```shell
hydroxide imap
```

### SMTP

For now, it only supports unencrypted local connections.

```shell
hydroxide smtp
```

## License

MIT
