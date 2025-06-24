# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Hydroxide is a third-party, open-source ProtonMail bridge designed for headless server environments. It translates standard email protocols (SMTP, IMAP, CardDAV) into ProtonMail API requests, allowing users to access ProtonMail with standard email clients.

## Architecture

### Core Components

- **protonmail/**: ProtonMail API client implementation
  - Main client in `protonmail.go` with API version 3
  - Handles authentication, messages, contacts, attachments, encryption
  - Uses OpenPGP for cryptographic operations
  - Label struct supports nested folder hierarchy via ParentID and Path fields

- **auth/**: Authentication and credential management
  - Manages bridge passwords and encrypted credential storage
  - Handles ProtonMail login, 2FA, and session management

- **imap/**: IMAP server implementation
  - Backend in `backend.go` implements go-imap interfaces
  - Database layer for mailbox and user management
  - **Full nested folder support** with ProtonMail Bridge-compatible structure
  - Proper distinction between Folders (exclusive) and Labels (non-exclusive)
  - IMAP RFC 3501 compliant folder attributes (HasChildren/HasNoChildren)

- **smtp/**: SMTP server implementation
  - Handles outgoing email through ProtonMail API
  - Supports sendmail interface

- **carddav/**: CardDAV server for contacts
  - Requires HTTPS reverse proxy in production
  - Tested with GNOME Evolution and Android DAVDroid

- **events/**: Real-time event management
  - Handles ProtonMail API events for synchronization

- **config/**: Configuration and TLS management

## Development Commands

### Building
```bash
go build ./cmd/hydroxide
```

### Running
```bash
# Authenticate with ProtonMail
./hydroxide auth <username>

# Run individual services
./hydroxide smtp    # Port 1025
./hydroxide imap    # Port 1143 (work-in-progress)
./hydroxide carddav # Port 8080

# Run all services together
./hydroxide serve
```

### Environment Variables
- `HYDROXIDE_BRIDGE_PASS`: Skip bridge password prompt

### Common Operations
```bash
# Check authentication status
./hydroxide status

# Export secret keys
./hydroxide export-secret-keys <username>

# Import/export messages
./hydroxide import-messages <username> [file]
./hydroxide export-messages -message-id <id> <username>

# Sendmail interface
./hydroxide sendmail <username> -- <args...>
```

## Key Technical Details

- **Language**: Go 1.23.8
- **Database**: BoltDB (bbolt) for local storage
- **Encryption**: ProtonMail's OpenPGP implementation
- **Default Ports**: SMTP (1025), IMAP (1143), CardDAV (8080)
- **API Endpoint**: https://mail.proton.me/api
- **Protocol Support**: Allows insecure auth for local connections
- **IMAP Features**: 
  - Full nested folder hierarchy support with unlimited depth
  - ProtonMail Bridge-compatible folder structure (Folders/ and Labels/)
  - Proper IMAP RFC 3501 compliance for mbsync/isync compatibility
  - Custom JSON unmarshaling for flexible API response handling

## Dependencies

Main dependencies include:
- ProtonMail go-crypto for OpenPGP operations
- emersion's Go email protocol libraries (go-imap, go-smtp, go-webdav)
- BoltDB (bbolt) for persistent storage
- Standard Go crypto and networking libraries

## Authentication Flow

1. User authenticates with ProtonMail credentials
2. 2FA support (TOTP only)
3. Mailbox password handling (single or two-password mode)
4. Generate bridge password for email clients
5. Store encrypted credentials locally

## Security Notes

- Bridge passwords are randomly generated 32-byte keys
- ProtonMail credentials encrypted with bridge password
- Supports TLS configuration for production use
- Client certificate authentication available