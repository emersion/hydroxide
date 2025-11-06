# CalDAV Support - Manual Testing Guide

## Prerequisites

1. ProtonMail account with calendar access
2. hydroxide built with CalDAV support
3. A CalDAV-compatible client (Thunderbird, Evolution, or KOrganizer)

## Test Procedure

### Step 1: Build hydroxide

```powershell
cd hydroxide
go build ./cmd/hydroxide
```

Expected output: Successful build with no errors

### Step 2: Authenticate

```powershell
.\hydroxide.exe auth your-protonmail-username
```

Expected output:
- Prompt for password
- Prompt for 2FA code (if enabled)
- Display of bridge password (save this!)

### Step 3: Start CalDAV Server

```powershell
.\hydroxide.exe caldav
```

Expected output:
```
CalDAV server listening on 127.0.0.1:8081
```

### Step 4: Configure Client

#### For Thunderbird:
1. Open Thunderbird
2. Go to Calendar view
3. Right-click on calendar list → "New Calendar..."
4. Select "On the Network" → Next
5. Username: your-protonmail-username
6. Location: `http://localhost:8081/caldav/your-protonmail-username/calendars/`
7. Password: (bridge password from Step 2)
8. Click "Find Calendars"

Expected result: List of your ProtonMail calendars appears

#### For Evolution:
1. Open Evolution
2. Go to Calendar
3. File → New → Calendar
4. Type: CalDAV
5. URL: `http://localhost:8081/caldav/your-protonmail-username/calendars/`
6. Enter credentials
7. Click "Apply"

Expected result: Calendar syncs successfully

### Step 5: Test Operations

#### Test 1: Read Events
1. View existing events in client
2. Verify they match events in ProtonMail web interface

Expected result: All events display correctly with proper:
- Title/Summary
- Date and time
- Description
- Location
- Notifications/Alarms

#### Test 2: Create Event
1. Create a new event in the calendar client:
   - Title: "CalDAV Test Event"
   - Date: Tomorrow
   - Time: 10:00 AM - 11:00 AM
   - Description: "Testing hydroxide CalDAV support"
   - Location: "Test Location"
2. Save the event
3. Check ProtonMail web interface

Expected result: Event appears in ProtonMail calendar

#### Test 3: Update Event
1. Open the test event created above
2. Modify:
   - Change time to 2:00 PM - 3:00 PM
   - Update description
3. Save changes
4. Check ProtonMail web interface

Expected result: Changes reflected in ProtonMail

#### Test 4: Delete Event
1. Delete the test event
2. Confirm deletion
3. Check ProtonMail web interface

Expected result: Event removed from ProtonMail calendar

### Step 6: Test Notifications

1. Create event with alarm/notification
2. Set reminder for 15 minutes before
3. Save event
4. Check in ProtonMail

Expected result: Notification settings saved correctly

### Step 7: Test Recurring Events

1. Create recurring event:
   - Title: "Weekly Meeting"
   - Recurrence: Every Monday
   - Time: 9:00 AM
2. Save event
3. Check ProtonMail

Expected result: Recurring event created with RRULE

## Verification Checklist

- [ ] Server starts without errors
- [ ] Can authenticate to CalDAV server
- [ ] Calendars list correctly
- [ ] Can view existing events
- [ ] Can create new events
- [ ] Can update events
- [ ] Can delete events
- [ ] Notifications work
- [ ] Recurring events work
- [ ] No errors in server log
- [ ] Events encrypted properly (verify in ProtonMail)

## Troubleshooting

### Connection Refused
- Check server is running on port 8081
- Verify no firewall blocking localhost

### Authentication Failed
- Verify bridge password is correct
- Re-run `hydroxide auth` if needed

### Events Not Syncing
- Check server logs for errors
- Verify ProtonMail API connectivity
- Ensure calendar has proper permissions

### Encryption Errors
- "openpgp: incorrect key" → Re-authenticate
- "invalid signature" → Check calendar permissions

## Success Criteria

✅ All test operations complete without errors
✅ Events correctly encrypted in ProtonMail
✅ Changes sync bidirectionally
✅ No data corruption or loss
✅ Client experience is smooth

## Performance Metrics

Expected performance:
- Initial calendar list: < 2 seconds
- Event list (100 events): < 5 seconds
- Create event: < 3 seconds
- Update event: < 3 seconds
- Delete event: < 2 seconds

## Security Verification

1. Check no plaintext calendar data in logs
2. Verify bridge password required for access
3. Confirm encryption used for all API calls
4. Test unauthorized access is denied

## Notes

- All times are in local timezone
- Server must remain running for sync
- Initial sync may take longer for large calendars
- Refresh interval depends on client settings

## Report Issues

If you encounter any issues:
1. Enable debug mode: `.\hydroxide.exe -debug caldav`
2. Capture full error messages
3. Note client and version used
4. Check if issue is reproducible
5. Report to GitHub issue #207
