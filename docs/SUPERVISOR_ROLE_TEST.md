# SUPERVISOR Role - Test Steps

## Prerequisites
1. Run the migration: `node db/migrate.js`
2. Have a PI account logged in
3. Have at least 2 researcher accounts (one to promote, one to assign)

## Database Migration

```sql
-- Run migration 008
-- Creates di_supervisor_researchers table
psql $DATABASE_URL -f migrations/008_add_supervisor_role.sql
```

Or use the migrate script:
```bash
node db/migrate.js
```

## Test Steps

### 1. Test Role Validation (PI adds new user with supervisor role)

**PowerShell:**
```powershell
# Login as PI first (use browser or get session cookie)
# Then test adding a new user with supervisor role
Invoke-RestMethod -Uri "http://localhost:8080/api/di/members" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"name":"Test Supervisor","researcher_id":"SUP001","institution_email":"supervisor@test.com","affiliation":"LiU","role":"supervisor"}' `
  -WebSession $session
```

**curl:**
```bash
curl -X POST http://localhost:8080/api/di/members \
  -H "Content-Type: application/json" \
  -b "connect.sid=YOUR_SESSION_COOKIE" \
  -d '{"name":"Test Supervisor","researcher_id":"SUP001","institution_email":"supervisor@test.com","affiliation":"LiU","role":"supervisor"}'
```

### 2. Test Promote Researcher to Supervisor

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/di/delegation/promote" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"user_id":"EXISTING_RESEARCHER_ID"}' `
  -WebSession $session
```

**curl:**
```bash
curl -X POST http://localhost:8080/api/di/delegation/promote \
  -H "Content-Type: application/json" \
  -b "connect.sid=YOUR_SESSION_COOKIE" \
  -d '{"user_id":"EXISTING_RESEARCHER_ID"}'
```

Expected response:
```json
{"success":true,"message":"User promoted to supervisor","user_id":"EXISTING_RESEARCHER_ID"}
```

### 3. Test Assign Researcher to Supervisor

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/di/delegation/assign" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"supervisor_id":"SUP001","researcher_id":"RES001"}' `
  -WebSession $session
```

**curl:**
```bash
curl -X POST http://localhost:8080/api/di/delegation/assign \
  -H "Content-Type: application/json" \
  -b "connect.sid=YOUR_SESSION_COOKIE" \
  -d '{"supervisor_id":"SUP001","researcher_id":"RES001"}'
```

### 4. Test Get Assignments

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/di/delegation/assignments?supervisor_id=SUP001" `
  -Method GET `
  -WebSession $session
```

**curl:**
```bash
curl http://localhost:8080/api/di/delegation/assignments?supervisor_id=SUP001 \
  -b "connect.sid=YOUR_SESSION_COOKIE"
```

### 5. Test Supervisor Login Redirect

1. Log out of PI account
2. Log in as the supervisor account
3. Should redirect to `supervisor-dashboard.html`

### 6. Test Supervision Endpoints (as Supervisor)

**Get assigned researchers:**
```bash
curl http://localhost:8080/api/di/supervision/researchers \
  -b "connect.sid=SUPERVISOR_SESSION_COOKIE"
```

**Get researcher files:**
```bash
curl http://localhost:8080/api/di/supervision/researchers/RES001/files \
  -b "connect.sid=SUPERVISOR_SESSION_COOKIE"
```

### 7. Test Authorization Enforcement

**Supervisor trying to access unassigned researcher (should fail):**
```bash
curl http://localhost:8080/api/di/supervision/researchers/UNASSIGNED_RES/files \
  -b "connect.sid=SUPERVISOR_SESSION_COOKIE"
```

Expected response:
```json
{"error":"Access denied. Researcher not assigned to you."}
```

**Researcher trying to access supervision endpoints (should fail):**
```bash
curl http://localhost:8080/api/di/supervision/researchers \
  -b "connect.sid=RESEARCHER_SESSION_COOKIE"
```

Expected response:
```json
{"error":"Access denied. Supervisor role required."}
```

### 8. Test Demote Supervisor

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/di/delegation/demote" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"user_id":"SUP001"}' `
  -WebSession $session
```

Expected: User role becomes "researcher", all assignments removed.

### 9. Test Unassign Researcher

**PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/di/delegation/unassign" `
  -Method POST `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{"supervisor_id":"SUP001","researcher_id":"RES001"}' `
  -WebSession $session
```

## UI Testing

### PI Dashboard
1. Go to User Management tab
2. Verify "Supervisor" option in role dropdown when adding users
3. Verify "Supervisor Delegation" section appears
4. Test promote/demote functionality
5. Test assign/unassign functionality
6. Verify assignments table updates

### Supervisor Dashboard
1. Login as supervisor
2. Verify redirect to supervisor-dashboard.html
3. Verify researcher list shows assigned researchers
4. Click on researcher to view files
5. Verify only View and Download buttons appear (no Delete, Approve, etc.)
6. Test View and Download functionality

## Rollback

To rollback the supervisor feature:

```sql
-- Remove all assignments
DELETE FROM di_supervisor_researchers;

-- Change all supervisors back to researchers
UPDATE di_allowlist SET role = 'researcher' WHERE role = 'supervisor';

-- Drop the table
DROP TABLE IF EXISTS di_supervisor_researchers;
```

## API Reference

### Delegation Endpoints (PI only)

| Endpoint | Method | Body | Description |
|----------|--------|------|-------------|
| `/api/di/delegation/promote` | POST | `{user_id}` | Promote researcher to supervisor |
| `/api/di/delegation/demote` | POST | `{user_id}` | Demote supervisor to researcher |
| `/api/di/delegation/assign` | POST | `{supervisor_id, researcher_id}` | Assign researcher to supervisor |
| `/api/di/delegation/unassign` | POST | `{supervisor_id, researcher_id}` | Remove assignment |
| `/api/di/delegation/assignments` | GET | Query: `supervisor_id` (optional) | List assignments |
| `/api/di/delegation/supervisors` | GET | - | List all supervisors |

### Supervision Endpoints (Supervisor only)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/di/supervision/researchers` | GET | List assigned researchers |
| `/api/di/supervision/researchers/:id/files` | GET | Get researcher's files (must be assigned) |
