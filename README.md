# hydroxide

A third-party, open-source ProtonMail CardDAV bridge.

## Usage

Your credentials will be stored on disk encrypted with a 32-byte random
password. When configuring your CardDAV client, you'll need this password.
You must setup an HTTPS reverse proxy to forward requests to `hydroxide`.

```shell
go get github.com/emersion/hydroxide
hydroxide auth <username>
hydroxide
```

Tested on GNOME (Evolution) and Android (DAVDroid).

## License

MIT
