# Entra ID (Azure AD) SAML Setup Guide

This guide configures Microsoft Entra ID as a SAML 2.0 Identity Provider for Enterprise IAM.

## Prerequisites

- An Entra ID tenant with permission to create Enterprise Applications.
- An Enterprise IAM tenant URL in this format: `https://[tenant].yoursaas.com/`.
- Access to your Enterprise IAM IdP settings page to enter:
  - IdP Entity ID
  - SSO URL
  - X.509 signing certificate
- A test user assigned to the Entra enterprise app.

## 1. Create the Enterprise Application in Entra ID

1. Go to Entra Admin Center.
2. Open **Enterprise applications**.
3. Select **New application**.
4. Select **Create your own application**.
5. Choose **Integrate any other application you don't find in the gallery (Non-gallery)**.
6. Name the app, then create it.

## 2. Configure SAML-based SSO

1. Open your new enterprise app.
2. Go to **Single sign-on**.
3. Choose **SAML**.
4. In **Basic SAML Configuration**, set:
   - **Identifier (Entity ID)**: `https://[tenant].yoursaas.com/`
   - **Reply URL (Assertion Consumer Service URL)**: `https://[tenant].yoursaas.com/wp-json/enterprise-auth/v1/saml/acs`
5. Save.

### Why these values

Enterprise IAM builds SAML SP settings dynamically from tenant URLs:
- SP Entity ID = tenant home URL
- ACS URL = WordPress REST route `/wp-json/enterprise-auth/v1/saml/acs`

## 3. Configure Entra claims (attribute mapping)

Enterprise IAM accepts NameID as primary email and falls back to these standard claim URIs.

### Required identity claims

- Email:
  - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
  - fallback: `urn:oid:0.9.2342.19200300.100.1.3`
  - fallback: `email`
- First name:
  - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname`
  - fallback: `urn:oid:2.5.4.42`
  - fallback: `givenName`
  - fallback: `firstName`
- Last name:
  - `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname`
  - fallback: `urn:oid:2.5.4.4`
  - fallback: `sn`
  - fallback: `lastName`

### Optional group claim

If you use role mapping in Enterprise IAM, include a group claim:
- `http://schemas.xmlsoap.org/claims/Group`
- fallback keys also accepted: `groups`, `memberOf`

## 4. Export certificate and IdP metadata values

From Entra SAML settings, copy these into Enterprise IAM:

- **IdP Entity ID** (Issuer)
- **Login URL** (Single Sign-On URL)
- **Certificate (Base64)** (X.509 signing cert)

Paste those into your SAML IdP configuration fields:
- `entity_id`
- `sso_url`
- `certificate`

## 5. Security requirements (must match)

Enterprise IAM enforces strict SAML validation. In effect:

- Assertion signatures are required.
- Response/message signatures are required.
- Unsolicited responses are rejected unless request correlation is valid.
- Destination checks are strict.

If your Entra app is not signing both assertions and response/messages as expected by your policy, login fails.

## 6. Test login

1. Start SSO from your tenant login flow.
2. Authenticate with assigned Entra test user.
3. Confirm redirect returns to your app and user is provisioned/logged in.

## Common Entra misconfiguration symptoms

- Invalid signature errors:
  - Usually wrong certificate, rotated cert not updated, or signing config mismatch.
- Generic login failure with `sso_error=federation_failed`:
  - Check server logs for `[DEBUG-fed-saml]` details and the `sso_error_ref` value.
