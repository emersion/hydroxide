 

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

 

 
### Authentication Failed
- Verify bridge password is correct
- Re-run `hydroxide auth` if needed

 

 

## Success Criteria

 All test operations complete without errors
 Events correctly encrypted in ProtonMail
 Changes sync bidirectionally
 No data corruption or loss
 Client experience is smooth

## Performance Metrics

Expected performance:
- Initial calendar list: < 2 seconds
- Event list (100 events): < 5 seconds
- Create event: < 3 seconds
- Update event: < 3 seconds
- Delete event: < 2 seconds

 
  
