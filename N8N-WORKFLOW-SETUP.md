# NATLAB GLP n8n Workflow Setup Guide

## 1. Required Environment Variables in n8n

Set these in your n8n instance Settings > Variables:

| Variable Name | Value | Description |
|---------------|-------|-------------|
| `NATLAB_GLP_API_KEY` | `natlab_glp_api_k3y_2024_s3cur3` | API key for backend authentication |
| `N8N_PUBLIC_BASE_URL` | `https://n8n-production-4d4f.up.railway.app` | Your n8n public URL (no trailing slash) |

## 2. Required Credentials in n8n

Ensure these credentials exist with exact names:

| Credential Name | Type | Notes |
|-----------------|------|-------|
| `OpenAi account` | OpenAI API | For AI review agent |
| `Gmail account 2` | Gmail OAuth2 | For sending emails |

## 3. Import the Workflow

1. Open n8n
2. Go to Workflows > Import from File
3. Select `n8n-workflow-di-review.json`
4. Review and save the workflow
5. **Activate the workflow** (toggle ON in top right)

## 4. Backend Endpoints Summary

### Existing Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/di/upload` | POST | Session | User uploads via portal |
| `/api/di/external-upload` | POST | API Key | n8n forwards uploads |
| `/api/di/submissions` | GET | API Key | List submissions |
| `/api/di/submissions/:id` | GET | API Key | Get single submission |
| `/api/di/submissions/:id` | PATCH | API Key | Update submission status |
| `/api/di/researchers` | GET | API Key | List researchers |

### New Endpoints (added for workflow)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/di/extract-text` | POST | API Key | Extract text from submission |
| `/api/di/sign` | POST | API Key + Token | Sign approved submission |
| `/api/di/download/:id` | GET | None | Download submission file |

## 5. Request/Response Examples

### POST /api/di/extract-text

**Request:**
```json
{
  "submission_id": "uuid-here"
}
```

**Response:**
```json
{
  "success": true,
  "submission_id": "uuid-here",
  "original_filename": "SOP_001.pdf",
  "sha256": "abc123...",
  "extracted_text": "Document content..."
}
```

### POST /api/di/sign

**Request:**
```json
{
  "submission_id": "uuid-here",
  "token": "32-char-hmac-token"
}
```

**Response:**
```json
{
  "success": true,
  "submission_id": "uuid-here",
  "signed_at": "2024-01-20T12:00:00.000Z",
  "signed_file_url": "https://natlab-glp-production.up.railway.app/api/di/download/uuid?signed=true",
  "original_filename": "SOP_001.pdf",
  "message": "Document signed successfully"
}
```

### GET /api/di/submissions/:id

**Response:**
```json
{
  "success": true,
  "submission": {
    "submission_id": "uuid",
    "researcher_id": "FJH",
    "affiliation": "LiU",
    "file_type": "SOP",
    "original_filename": "SOP_001.pdf",
    "status": "PENDING",
    "sender_email": "frank.hernandez@liu.se",
    "ai_review": { ... },
    "revision_comments": null,
    "signed_at": null,
    "created_at": "2024-01-20T12:00:00.000Z"
  }
}
```

## 6. Webhook URLs

After importing and activating the workflow:

| Webhook | URL | Method |
|---------|-----|--------|
| Intake | `https://n8n-production-4d4f.up.railway.app/webhook/di-intake` | POST |
| Approve | `https://n8n-production-4d4f.up.railway.app/webhook/di-approve` | GET |
| Revise Form | `https://n8n-production-4d4f.up.railway.app/webhook/di-revise` | GET |
| Revise Submit | `https://n8n-production-4d4f.up.railway.app/webhook/di-revise-submit` | POST |

## 7. Test Plan

### Test 1: Intake Upload

```bash
# Create a test file
echo "Test SOP Document Content" > test_sop.txt

# Upload via curl
curl -X POST "https://n8n-production-4d4f.up.railway.app/webhook/di-intake" \
  -F "researcher_id=FJH" \
  -F "affiliation=LiU" \
  -F "fileType=SOP" \
  -F "original_filename=test_sop.txt" \
  -F "sender_email=frank.hernandez@liu.se" \
  -F "researcher_name=Frank J. Hernandez" \
  -F "file=@test_sop.txt"
```

**Expected:**
- Returns JSON with `submission_id`
- Email sent to frank.hernandez@liu.se with review details
- Database updated with submission

### Test 2: Approve Flow

```bash
# Generate token (Python example)
python3 -c "
import hmac, hashlib
submission_id = 'YOUR_SUBMISSION_ID'
secret = 'natlab_glp_api_k3y_2024_s3cur3'
token = hmac.new(secret.encode(), submission_id.encode(), hashlib.sha256).hexdigest()[:32]
print(f'Token: {token}')
print(f'URL: https://n8n-production-4d4f.up.railway.app/webhook/di-approve?submission_id={submission_id}&token={token}')
"

# Or just click the APPROVE link in the review email
```

**Expected:**
- Submission signed
- Status updated to APPROVED
- Confirmation email sent to researcher
- Success page displayed

### Test 3: Revise Flow

```bash
# Click the REVISE link in the email to see the form, then submit:
curl -X POST "https://n8n-production-4d4f.up.railway.app/webhook/di-revise-submit" \
  -d "submission_id=YOUR_SUBMISSION_ID" \
  -d "token=YOUR_TOKEN" \
  -d "comments=Please add version number and approval signatures."
```

**Expected:**
- Status updated to REVISION_NEEDED
- Comments stored in database
- Email sent to researcher with comments
- Success page displayed

## 8. AI Review Schema

The AI agent outputs this exact JSON schema:

```json
{
  "metadata": {
    "submission_id": "string",
    "fileType": "SOP|DATA|UNKNOWN",
    "researcher_id": "string",
    "researcher_name": "string",
    "affiliation": "string",
    "filename": "string",
    "file_hash_sha256": "string",
    "download_url": "string",
    "sender_email": "string"
  },
  "executive_summary": {
    "short_summary": "string",
    "overall_quality": "HIGH|MEDIUM|LOW",
    "primary_conclusion": "string"
  },
  "evaluation": {
    "review_mode": "SOP_REVIEW|ALCOA_DATA_REVIEW",
    "decision": "APPROVE|REVISE",
    "confidence_score": 0.0
  },
  "checklist": [
    {
      "category": "SOP|ALCOA",
      "item": "string",
      "status": "PASS|FAIL|UNKNOWN",
      "evidence": "string",
      "severity": "MINOR|MAJOR"
    }
  ],
  "missing_or_unclear_items": ["string"],
  "suggested_revisions": ["string"],
  "red_flags": ["string"],
  "human_reviewer_guidance": {
    "what_to_verify_in_original_file": ["string"],
    "questions_for_researcher": ["string"]
  }
}
```

## 9. Security Notes

- All approval/revise links include HMAC tokens derived from submission_id + API_SECRET_KEY
- Tokens are validated server-side before any action
- API endpoints require x-api-key header
- Credentials are referenced by name, not embedded in workflow JSON

## 10. Troubleshooting

### Workflow not triggering
- Check workflow is ACTIVE (toggle ON)
- Verify webhook URL matches exactly
- Check n8n logs for errors

### Email not sending
- Verify Gmail credential is connected and authorized
- Check Gmail sending limits

### AI review failing
- Verify OpenAI credential is valid
- Check if API quota is available
- Review n8n execution logs for error details

### Token validation failing
- Ensure NATLAB_GLP_API_KEY matches in n8n and backend
- Check submission_id is correct UUID format
