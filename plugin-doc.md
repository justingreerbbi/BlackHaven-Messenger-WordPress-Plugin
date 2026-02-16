# BlackHaven Messenger — Plugin & Mobile API Documentation

This document describes the **BlackHaven Messenger** WordPress plugin from a **mobile app integration** point of view:

-   REST API base paths, endpoints, request/response shapes
-   Authentication & token handling
-   Data model (WordPress options + custom DB tables)
-   Hooks/filters you can rely on
-   Known implementation mismatches (important for client interoperability)

Source of truth for this doc is the plugin code in:

-   [blackhaven-messenger.php](blackhaven-messenger.php)
-   [includes/class-bh-messenger-rest.php](includes/class-bh-messenger-rest.php)
-   [includes/class-bh-options.php](includes/class-bh-options.php)

---

## 1) High-level Overview

BlackHaven Messenger adds:

1. **Custom DB tables** for access tokens, conversations, membership, messages, and encryption key material.
2. A **REST API namespace** intended for the BlackHaven Messenger Mobile App.
3. An admin UI for settings + connection QR.

The REST API is implemented by `BH_Messenger_REST`.

---

## 2) REST API Base URL

WordPress REST API base is:

-   `https://<your-site>/wp-json/`

This plugin registers routes under:

-   `blackhaven-messenger/v1`

So an example full endpoint is:

-   `https://<your-site>/wp-json/blackhaven-messenger/v1/authorize`

### Connection Info QR (admin UI)

The admin Connection Info page displays a configurable **Server URL**:

-   Option name: `bh_messenger_server_url`
-   Default shown in UI: `get_site_url() . '/wp-json/blackhaven/v1/messenger'`

Important: this default **does not match** the actual namespace used by the plugin (`blackhaven-messenger/v1`). If your mobile app reads the QR JSON, ensure it can handle a corrected server URL.

See: [includes/class-bh-options.php](includes/class-bh-options.php)

---

## 3) Authentication Model

### 3.1 Access Token issuance

Endpoint:

-   `POST /wp-json/blackhaven-messenger/v1/authorize`

This endpoint accepts WordPress username + password and returns an **access token** and a **refresh token**.

-   Stored server-side as **hashed** values in the `bh_access_tokens` table.
-   The plugin currently enforces **one active token per user** (it deletes existing rows for that user).

### 3.2 How to authenticate requests

Most endpoints require:

1. `Authorization: Bearer <access_token>` header
2. `user_id` parameter (body or request param)

Token validation logic:

-   The plugin **does not allow** the token in a query parameter (`access_token`) and will return 401 if you attempt that.
-   It looks up the token record by `user_id` and checks:
    -   `expires_at > now`
    -   `wp_check_password(<presented_token>, <stored_hashed_token>)`

See: `check_access_token()` in [includes/class-bh-messenger-rest.php](includes/class-bh-messenger-rest.php)

### 3.3 Token expiry

Token lifetime is controlled by:

-   Option: `bh_messenger_advanced_options[access_token_lifetime]` (seconds)
    -   Default: `3600` (1 hour)
    -   If set to `0`, plugin treats as “never expire” and sets expiry ~10 years out.

Filter:

-   `blackhaven_messenger_authorize_access_token_expires` — can override the computed expiry.

### 3.4 Refresh tokens

`/authorize` returns `refresh_token` and stores a hashed refresh token.

Important: the current codebase **does not expose a refresh endpoint** (e.g. `/refresh`) and there is no implemented token rotation. A mobile app should assume:

-   If a request returns 401 due to expiry, the app must re-authenticate using username/password (unless you add a refresh endpoint).

---

## 4) Common Request / Response Conventions

### 4.1 Content types

Each endpoint attempts to read JSON body using:

-   `$request->get_body_params()`
-   fallback: `json_decode($request->get_body(), true)`

Mobile clients should send:

-   `Content-Type: application/json`

### 4.2 Error responses

The plugin returns `WP_Error` for failure cases. Over HTTP this is typically serialized by WP REST into JSON similar to:

```json
{
	"code": "invalid_login",
	"message": "Invalid username or password",
	"data": { "status": 401 }
}
```

Status codes used include: `400`, `401`, `403`, `500`.

---

## 5) REST Endpoints (Mobile App API)

All endpoints below are registered in [includes/class-bh-messenger-rest.php](includes/class-bh-messenger-rest.php).

### 5.1 `POST /authorize`

Purpose: exchange WordPress credentials for an access token.

**Auth:** none (`permission_callback` is `__return_true`).

**Request JSON**

```json
{
	"username": "wp_username",
	"password": "wp_password"
}
```

**Success response (200)**

```json
{
	"success": true,
	"token": "<access_token>",
	"refresh_token": "<refresh_token>",
	"expires": "YYYY-MM-DD HH:MM:SS",
	"created": "YYYY-MM-DD HH:MM:SS",
	"user_data": { "ID": 123 }
}
```

**Errors**

-   401 `invalid_login`
-   500 `db_error`

**Extensibility**

-   Filter `blackhaven_messenger_authorize_user_info_data` can add more user fields to `user_data`.

---

### 5.2 `POST /payload`

Purpose: fetch the initial dataset needed by the mobile app after login.

**Auth:** required.

**Required**

-   Header: `Authorization: Bearer <token>`
-   Param: `user_id` (must match the authenticated user)

**Request JSON (minimal)**

```json
{ "user_id": 123 }
```

**Response (200)**

```json
{
	"users": [
		{
			"ID": 456,
			"display_name": "Alice",
			"ik_pub_b64": "...",
			"sig_pub_b64": "...",
			"spk_pub_b64": "...",
			"spk_sig_b64": "..."
		}
	],
	"conversations": [
		{
			"ID": 10,
			"type": "private",
			"created_by": 123,
			"created_at": "...",
			"session_key": "...",
			"conversation_name": "Alice",
			"members": [
				{ "ID": 123, "display_name": "You", "ik_pub_b64": "...", "created_at": "..." },
				{ "ID": 456, "display_name": "Alice", "ik_pub_b64": "...", "created_at": "..." }
			],
			"latest_message": {
				"ID": 999,
				"sender_id": 456,
				"message_text": "<ciphertext>",
				"nonce": "<nonce>",
				"created_at": "..."
			}
		}
	]
}
```

Notes:

-   Private conversation names are derived server-side as the “other member display_name”.
-   Group conversation names are currently hard-coded to `"Group Chat"`.

---

### 5.3 `POST /identity/sync`

Purpose: publish/update the user’s public identity keys used for E2E encryption.

**Auth:** required.

**Required**

-   Header: `Authorization: Bearer <token>`
-   Body must include `user_id` (permission check requires it)

**Request JSON**

```json
{
	"user_id": 123,
	"ik_pub_b64": "<base64>",
	"sig_pub_b64": "<base64>",
	"spk_pub_b64": "<base64>",
	"spk_sig_b64": "<base64-or-text>"
}
```

**Response (200)**

```json
{ "success": true, "user_id": 123 }
```

---

### 5.4 `POST /users`

Purpose: list users available for chat.

**Auth:** required by route config.

Important implementation note:

-   The handler `get_users()` is defined without a `$request` parameter, but WP REST will pass the request object to the callback. On modern PHP versions, this can raise a **fatal “Too many arguments”** error.

Also, the SQL inside `get_users()` references columns (`public_key`, `key_type`, `expires_at`) that do not exist in the created `bh_user_keys` schema (which uses `ik_pub_b64`, `sig_pub_b64`, `spk_pub_b64`, `spk_sig_b64`).

If you plan to use `/users` from the mobile app, this endpoint likely needs server-side fixes first.

---

### 5.5 `POST /conversations`

Purpose: list conversations for the authenticated user.

**Auth:** required.

**Request JSON**

```json
{ "user_id": 123 }
```

**Response (200)**

-   Returns a list of conversation records with an added `members` array.

Important implementation note:

-   Similar to `/users`, the members query references `uk.public_key`, `uk.key_type`, `uk.expires_at` which do not match the table schema created on activation.

---

### 5.6 `POST /conversations/start-private`

Purpose: create a private conversation (1:1).

**Auth:** required.

**Request JSON**

```json
{
	"user_id": 123,
	"other_user_id": 456,
	"encrypted_session_key": "<ciphertext>"
}
```

**Response (200)**

```json
{ "success": true, "conversation_id": 10 }
```

Notes:

-   The server stores `encrypted_session_key` in the `bh_conversations.session_key` column.
-   The endpoint does not return members/keys; the client is expected to fetch those via `/payload` or other endpoints.
-   The plugin currently does not check for an existing conversation between two users.

---

### 5.7 `POST /conversations/start-group`

Purpose: create a group conversation and send an initial message.

**Auth:** required.

**Request JSON**

```json
{
	"user_id": 123,
	"member_ids": [456, 789],
	"encrypted_message": "<ciphertext>"
}
```

`member_ids` can also be a comma-separated string (e.g. `"456,789"`).

**Response (200)**

```json
{ "success": true, "conversation_id": 20 }
```

Important implementation note:

-   The code attempts to insert `encrypted_text` into the messages table, but the schema defines `message_text` and `nonce`. This likely breaks group creation without server changes.

---

### 5.8 `POST /conversations/get-messages`

Purpose: fetch all messages for a conversation.

**Auth:** required.

**Request JSON**

```json
{ "user_id": 123, "conversation_id": 10 }
```

**Response (200)**

```json
{
	"conversation": { "ID": 10, "type": "private", "session_key": "..." },
	"members": [{ "ID": 123, "display_name": "..." }],
	"messages": [
		{
			"id": 999,
			"conversation_id": 10,
			"sender_id": 456,
			"message_text": "<ciphertext>",
			"nonce": "<nonce>",
			"file_path": null,
			"created_at": "..."
		}
	]
}
```

Notes:

-   The server enforces membership and returns 403 if you are not a member.
-   There is no pagination yet.

---

### 5.9 `POST /conversations/send-message`

Purpose: send a message to an existing conversation.

**Auth:** required.

**Request JSON**

```json
{
	"user_id": 123,
	"conversation_id": 10,
	"message": "<ciphertext>",
	"nonce": "<nonce>"
}
```

**Response (200)**

```json
{ "success": true, "message_id": 1000 }
```

Side-effects / hooks:

-   If the sender is not a member, the plugin fires:
    -   `do_action('blackhaven_messenger_unauthorized_conversation_access_attempt', [ ...context... ])`
        and returns 403.

---

## 6) Custom Database Tables

Tables are created on activation in [blackhaven-messenger.php](blackhaven-messenger.php).

### 6.1 `wp_bh_access_tokens`

Columns:

-   `ID` (PK)
-   `user_id`
-   `token` (hashed)
-   `refresh_token` (hashed)
-   `expires_at` (DATETIME)
-   `created_at`

### 6.2 `wp_bh_conversations`

Columns:

-   `ID` (PK)
-   `type` (`private` | `group`)
-   `created_by`
-   `created_at`
-   `session_key` (VARBINARY(2048), used for encrypted session key)
-   `conversation_name` (optional)

### 6.3 `wp_bh_conversation_members`

Columns:

-   `conversation_id` (PK part)
-   `user_id` (PK part)
-   `joined_at`

### 6.4 `wp_bh_messages`

Columns:

-   `id` (PK)
-   `conversation_id`
-   `sender_id`
-   `message_text` (TEXT; stored ciphertext)
-   `nonce` (VARCHAR(100))
-   `file_path` (optional)
-   `created_at`

### 6.5 `wp_bh_user_keys`

Columns:

-   `user_id` (PK)
-   `ik_pub_b64` (CHAR(44))
-   `sig_pub_b64` (CHAR(44))
-   `spk_pub_b64` (CHAR(44))
-   `spk_sig_b64` (TEXT)
-   `created_at`

### 6.6 `wp_bh_conversation_keys`

Columns:

-   `conversation_id` (PK part)
-   `user_id` (PK part)
-   `encrypted_key` (VARBINARY(2048))
-   `created_at`

---

## 7) WordPress Options (Settings)

### Basic

-   `bh_messenger_option` (set via admin UI)
    -   `enable_api` (1/0)

### Advanced

-   `bh_messenger_advanced_options`
    -   `access_token_lifetime` (seconds)
    -   `remove_data_on_deactivation` (1/0)
    -   `debug` (1/0)
    -   `force_blackhaven_vpn_usage` (1/0) — UI/flag only; the API layer does not enforce VPN.

### Connection

-   `bh_messenger_server_url` — the URL displayed in the connection QR

---

## 8) Admin AJAX

There is an admin-only AJAX action in:

-   [includes/admin-ajax.php](includes/admin-ajax.php)

Action:

-   `wp_ajax_blackhaven_messenger_action`

This is a placeholder example handler returning `{ "message": "AJAX request received." }` and is not used by the mobile REST API.

---

## 9) Security Notes for Mobile Apps

-   Always use HTTPS; bearer tokens are equivalent to passwords.
-   Do not send tokens in query params; the plugin rejects `access_token` in URL to reduce leakage.
-   Store tokens securely (Keychain / Keystore) and treat `refresh_token` as equally sensitive.
-   Expect that the server may return `401` for expiry and currently requires re-auth (no refresh endpoint implemented).

---

## 10) Known Implementation Mismatches (Client-impacting)

These are important if you are building a mobile client against the plugin as-is:

1. **Connection QR default URL mismatch**: UI default is `/wp-json/blackhaven/v1/messenger`, but plugin registers `blackhaven-messenger/v1` routes.
2. **`/users` callback signature** likely breaks due to missing `$request` parameter in PHP 8+.
3. **`bh_user_keys` schema vs code mismatch**:
    - Schema provides `ik_pub_b64`, `sig_pub_b64`, `spk_pub_b64`, `spk_sig_b64`
    - Some endpoints query `public_key`, `key_type`, `expires_at` which are not present.
4. **Group conversation message insert mismatch**:
    - Code inserts `encrypted_text` into messages table, but schema uses `message_text` and requires `nonce`.
5. **API enable option naming inconsistency**:
    - Activation creates `bh_messenger_options` (plural) but runtime checks `bh_messenger_option` (singular) for `enable_api`.

If you want, I can also patch these issues so the API is internally consistent for your mobile app.
