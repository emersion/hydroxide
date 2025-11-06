# CalDAV Support - Proof of Concept

## Overview

This document demonstrates the CalDAV implementation for hydroxide, enabling calendar synchronization with ProtonMail calendars.

## Implementation Details

### Architecture

The CalDAV implementation consists of three main components:

1. **CalDAV Backend** (`caldav/caldav.go`)
   - Implements the `caldav.Backend` interface from `go-webdav`
   - Handles calendar listing, event CRUD operations
   - Manages encryption/decryption of calendar data

2. **ProtonMail Calendar API** (`protonmail/calendar.go`)
   - Extended API client with calendar endpoints
   - Calendar bootstrapping and key management
   - Event encryption using OpenPGP

3. **Server Integration** (`cmd/hydroxide/main.go`)
   - New `caldav` command to run standalone CalDAV server
   - Integration with `serve` command (port 8081)
   - Authentication and event management

### Key Features

#### 1. Calendar Operations
- **List Calendars**: Retrieve all calendars from ProtonMail account
- **Get Calendar**: Fetch specific calendar details
- **List Events**: Get events with optional time-range filtering
- **Create/Update Events**: Full support for event creation and modification
- **Delete Events**: Remove calendar events

#### 2. Encryption Support
- **Shared Event Cards**: Signed and encrypted event data
- **Calendar Event Cards**: Calendar-specific encrypted data
- **Session Key Management**: Automatic key generation and reuse
- **OpenPGP Integration**: Full end-to-end encryption

#### 3. Client Compatibility
Tested and verified with:
-  GNOME Evolution (Linux)
-  Mozilla Thunderbird (Cross-platform)
-  KDE KOrganizer (Linux)

### Security

- All calendar data is encrypted end-to-end using OpenPGP
- Private keys are decrypted only in memory
- Bridge password protects local authentication
- No calendar data stored in plaintext

## Usage

### 1. Start CalDAV Server

```bash
# Standalone CalDAV server
hydroxide caldav

# Run all servers (includes CalDAV on port 8081)
hydroxide serve
```

### 2. Configure Calendar Client

#### Thunderbird Setup
1. Open Thunderbird and go to Calendar
2. Right-click in calendar list → New Calendar → On the Network
3. Enter CalDAV URL: `http://localhost:8081/caldav/[username]/calendars/`
4. Username: Your ProtonMail username
5. Password: Bridge password (from `hydroxide auth`)

#### Evolution Setup
1. Open Evolution → Calendar
2. File → New → Calendar
3. Type: CalDAV
4. URL: `http://localhost:8081/caldav/[username]/calendars/`
5. Username: ProtonMail username
6. Password: Bridge password

#### KOrganizer Setup
1. Settings → Configure KOrganizer → Calendars
2. Add → DAV Groupware Resource
3. Server: `http://localhost:8081`
4. Path: `/caldav/[username]/calendars/`
5. Username/Password as above

## Technical Implementation

### Event Encryption Flow

```
Client (iCal) → CalDAV Server → Encryption Layer → ProtonMail API
                                       ↓
                            Shared Cards (Signed)
                            Calendar Cards (Encrypted)
```

### Event Properties Distribution

**Shared Signed Fields** (visible to all calendar members):
- UID, DTSTAMP, DTSTART, DTEND
- RECURRENCE-ID, RRULE, EXDATE
- ORGANIZER, SEQUENCE

**Shared Encrypted Fields** (encrypted, shared):
- UID, DTSTAMP, CREATED
- DESCRIPTION, SUMMARY, LOCATION

**Calendar Signed Fields** (calendar-specific):
- UID, DTSTAMP, EXDATE
- STATUS, TRANSP

**Calendar Encrypted Fields** (calendar-specific, encrypted):
- UID, DTSTAMP, COMMENT

### API Endpoints

- `GET /calendar/v1` - List calendars
- `GET /calendar/v1/{id}/bootstrap` - Get calendar keys
- `GET /calendar/v1/{id}/events` - List events
- `GET /calendar/v1/{id}/events/{eventId}` - Get event
- `PUT /calendar/v1/{id}/events/sync` - Create/Update/Delete events

## Performance Considerations

- **Caching**: User public keys are cached to reduce API calls
- **Lazy Loading**: Calendars and events loaded on-demand
- **Session Keys**: Reused for multiple operations

## Known Limitations

1. **No Attendee Invitations**: Currently doesn't send invitation emails
2. **No Calendar Creation**: Cannot create new calendars via CalDAV
3. **Limited Recurring Events**: Basic support for RRULE
4. **No Offline Mode**: Requires active ProtonMail API connection

## Error Handling

Common errors and solutions:

### "openpgp: incorrect key"
- **Cause**: Wrong calendar key or passphrase
- **Solution**: Re-bootstrap calendar or check key permissions

### "openpgp: invalid signature: EdDSA verification failure"
- **Cause**: Signature verification failed
- **Solution**: Verify user has access to calendar and keys are valid

### "could not find CalendarMemberView"
- **Cause**: User not a member of the calendar
- **Solution**: Check calendar sharing settings in ProtonMail

## Development Notes

### Dependencies

```go
github.com/emersion/go-ical v0.0.0-20240127095438-fc1c9d8fb2b6
github.com/emersion/go-webdav v0.6.0
github.com/ProtonMail/go-crypto v1.3.0
```

### Code Structure

```
caldav/
  └── caldav.go         # CalDAV backend implementation

protonmail/
  ├── calendar.go       # Calendar API methods
  ├── crypto.go         # Encryption utilities
  └── protonmail.go     # Base API client

cmd/hydroxide/
  └── main.go           # Server and CLI integration
```

 

## Credits

This implementation is based on:
- Original work by @emersion in the `caldav` branch
- Significant contributions by @zCri (PR #282)
- Community testing and feedback from issue #207

## License

MIT License - Same as hydroxide project

