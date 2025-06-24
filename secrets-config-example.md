# AWS Secrets Manager Configuration Examples

## 1. Google API Credentials Secret

**Secret Name:** `my-google-api-credentials`
**Secret Type:** Other type of secret
**Secret Value:** Plain text JSON

```json
{
  "type": "service_account",
  "project_id": "your-google-project-id",
  "private_key_id": "your-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n",
  "client_email": "your-service-account@your-project.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project.iam.gserviceaccount.com"
}
```

## 2. AutoGreens Configuration Secret

**Secret Name:** `autogreens-config`
**Secret Type:** Other type of secret
**Secret Value:** Plain text JSON

```json
{
  "spreadsheet_name": "DIALNA-ASSORTIMENT",
  "gy_username_market": "your-gy-username-market",
  "gy_password_market": "your-gy-password-market",
  "mc_username_market": "your-mycadencier-username",
  "mc_password_market": "your-mycadencier-password",
  "mc_shop_id_market": "0538",
  "mc_target_store_id_market": "011431",
  "gy_username_express": "your-gy-username-express",
  "gy_password_express": "your-gy-password-express",
  "mc_username_express": "your-mycadencier-username-express",
  "mc_password_express": "your-mycadencier-password-express",
  "mc_shop_id_express": "0538",
  "mc_target_store_id_express": "011431"
}
```

## Configuration Notes

### MyCadencier API Response Format

The function now correctly handles the MyCadencier API response format:

- **Product Reference**: Uses `"id"` field (e.g., "00940566")
- **Unit Price**: Uses `"baseAmountPrice"` field (e.g., 1.73)
- **Sales Price**: Uses `"salesPrice"` field for reference
- **Product Title**: Uses `"title_fr"` for French names

### Google Sheets Column Mapping

- **MC-REF** (Column 2): Product reference from MyCadencier `"id"` field
- **MC-MKT-UNIT** (Column 8): Market unit price formatted as "1,79 €"
- **MC-EXP-UNIT** (Column 9): Express unit price formatted as "1,79 €"
- **D-MAJ MC-MKT** (Column 18): Market price update timestamp
- **D-MAJ MC-EXP** (Column 19): Express price update timestamp

### Google Service Account Setup

1. Go to Google Cloud Console
2. Create a new project or select existing one
3. Enable Google Sheets API and Google Drive API
4. Create a Service Account
5. Download the JSON key file
6. Share your Google Sheet with the service account email
7. Copy the JSON content to AWS Secrets Manager

### MyCadencier Credentials

- Use the same credentials from your working MYCADENCIER_RMZN project
- Store codes and target store IDs should match your requirements
- You can use the same credentials for both market and express if they're the same

### Google Sheets Permission

Make sure your Google Sheet is shared with the service account email with "Editor" permissions.

### AWS Region

All secrets should be created in the same region as your Lambda function (eu-west-3 by default).

## Security Best Practices

1. **Restrict Secret Access**: Only grant access to the Lambda execution role
2. **Rotate Credentials**: Regularly update MyCadencier passwords
3. **Monitor Access**: Enable CloudTrail for secret access logging
4. **Use Resource-Based Policies**: Limit which Lambda functions can access secrets

## CLI Commands for Secret Creation

```bash
# Create Google API credentials secret
aws secretsmanager create-secret \
    --name "my-google-api-credentials" \
    --description "Google Service Account credentials for Sheets API" \
    --secret-string file://google-service-account.json \
    --region eu-west-3

# Create AutoGreens configuration secret
aws secretsmanager create-secret \
    --name "autogreens-config" \
    --description "MyCadencier and application configuration" \
    --secret-string file://autogreens-config.json \
    --region eu-west-3
```
