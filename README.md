# hydroxide

A third-party, open-source ProtonMail bridge. For power users only, designed to
run on a server.

hydroxide supports CardDAV, IMAP and SMTP.

Rationale:

* No GUI, only a CLI (so it runs in headless environments)
* Standard-compliant (we don't care about Microsoft Outlook)
* Fully open-source

Feel free to join the IRC channel: #emersion on Libera Chat.

## How does it work?

hydroxide is a server that translates standard protocols (SMTP, IMAP, CardDAV)
into ProtonMail API requests. It allows you to use your preferred e-mail clients
and `git-send-email` with ProtonMail.

    +-----------------+             +-------------+  ProtonMail  +--------------+
    |                 | IMAP, SMTP  |             |     API      |              |
    |  E-mail client  <------------->  hydroxide  <-------------->  ProtonMail  |
    |                 |             |             |              |              |
    +-----------------+             +-------------+              +--------------+

## Setup

### Go

hydroxide is implemented in Go. Head to [Go website](https://golang.org) for
setup information.

### Installing

Start by installing hydroxide:

```shell
git clone https://github.com/emersion/hydroxide.git
go build ./cmd/hydroxide
```

Then you'll need to login to ProtonMail via hydroxide, so that hydroxide can
retrieve e-mails from ProtonMail. You can do so with this command:

```shell
hydroxide auth <username>
```

Once you're logged in, a "bridge password" will be printed. Don't close your
terminal yet, as this password is not stored anywhere by hydroxide and will be
needed when configuring your e-mail client.

Your ProtonMail credentials are stored on disk encrypted with this bridge
password (a 32-byte random password generated when logging in).

## Usage

hydroxide can be used in multiple modes.

> Don't start hydroxide multiple times, instead you can use `hydroxide serve`.
> This requires ports 1025 (smtp), 1143 (imap), and 8080 (carddav).

### SMTP

To run hydroxide as an SMTP server:

```shell
hydroxide smtp
```

Once the bridge is started, you can configure your e-mail client with the
following settings:

* Hostname: `localhost`
* Port: 1025
* Security: none
* Username: your ProtonMail username
* Password: the bridge password (not your ProtonMail password)

### CardDAV

You must setup an HTTPS reverse proxy to forward requests to `hydroxide`.

```shell
hydroxide carddav
```

Tested on GNOME (Evolution) and Android (DAVDroid).

### IMAP

IMAP support includes full nested folder hierarchy and comprehensive TLS support, compatible with standard email clients like mbsync/isync.

Features:
- Full nested folder support with unlimited depth
- ProtonMail Bridge-compatible folder structure (Folders/ and Labels/)
- IMAP RFC 3501 compliance for proper email client integration
- Support for both ProtonMail folders and labels
- Complete TLS support with automatic certificate generation

Connection options:

```shell
# Unencrypted IMAP
hydroxide imap

# IMAP with STARTTLS using auto-generated certificates (easiest)
hydroxide -tls-auto-generate imap

# IMAP with STARTTLS using your own certificates
hydroxide -tls-cert cert.pem -tls-key key.pem imap

# IMAP with implicit TLS (IMAPS)
hydroxide -tls-cert cert.pem -tls-key key.pem -imap-tls-mode implicit imap
```

TLS Options:
- **Auto-generated certificates**: Use `-tls-auto-generate` for automatic self-signed certificates
- **Custom certificates**: Provide your own with `-tls-cert` and `-tls-key`
- **STARTTLS mode** (default): Server starts unencrypted and upgrades to TLS when requested
- **Implicit TLS mode**: Server requires TLS from connection start (IMAPS)
- **Client certificate authentication**: Optional CA verification with `-tls-client-ca`

Certificate Storage:
- Auto-generated certificates are saved to `~/.config/hydroxide/` (Linux/macOS) or `%APPDATA%\hydroxide\` (Windows)
- Certificates are valid for 1 year and include localhost + 127.0.0.1

Security Notes:
- Auto-generated certificates are self-signed and suitable for local use
- For production deployments, use custom certificates from a trusted CA
- STARTTLS mode is recommended for compatibility with most email clients
- Implicit TLS mode (IMAPS) provides immediate encryption but may require port 993

Tested with mbsync/isync for Maildir synchronization.

## License

MIT
