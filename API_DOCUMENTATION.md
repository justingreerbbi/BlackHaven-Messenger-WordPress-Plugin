# BlackHaven Messenger API Documentation

## Overview

BlackHaven Messenger is a WordPress plugin that provides a secure, end-to-end encrypted messaging API. This documentation covers all available REST API endpoints, their parameters, expected payloads, and responses.

**Base URL:** `https://your-wordpress-site.com/wp-json/blackhaven-messenger/v1/`

**Authentication:** All endpoints (except `/authorize`) require a Bearer token in the Authorization header and a `user_id` parameter.

## Authentication

### Authorization Header
```
Authorization: Bearer <access_token>
```

### Common Parameters
Most endpoints require:
- `user_id` (integer): The authenticated user's WordPress user ID

---

## Endpoints

### 1. Authorize User

Authenticate a user and obtain an access token.

**Endpoint:** `POST /authorize`

**Authentication:** None required

**Request Body (form-data):**
| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| username  | string | Yes      | WordPress username |
| password  | string | Yes      | WordPress password |

**Response (Success - 200):**
```json
{
  "success": true,
  "token": "string",
  "refresh_token": "string",
  "expires": "2025-12-24 12:00:00",
  "created": "2024-12-24 12:00:00",
  "user_data": {
    "ID": 123,
    "display_name": "John Doe"
  }
}
```

**Response (Error - 401):**
```json
{
  "code": "invalid_login",
  "message": "Invalid username or password",
  "data": { "status": 401 }
}
```

---

### 2. Initial Payload

Get initial data including users with keys and user's conversations.

**Endpoint:** `POST /payload`

**Authentication:** Bearer token required

**Request Body:** None (user_id from auth)

**Response (Success - 200):**
```json
{
  "users": [
    {
      "ID": 124,
      "display_name": "Jane Smith",
      "ik_pub_b64": "base64_string",
      "sig_pub_b64": "base64_string",
      "spk_pub_b64": "base64_string",
      "spk_sig_b64": "base64_string"
    }
  ],
  "conversations": [
    {
      "ID": 1,
      "type": "private",
      "created_by": 123,
      "created_at": "2024-12-24 12:00:00",
      "session_key": "encrypted_key",
      "conversation_name": "Jane Smith",
      "members": [
        {
          "ID": 123,
          "display_name": "John Doe",
          "ik_pub_b64": "base64_string",
          "created_at": "2024-12-24 12:00:00"
        }
      ],
      "latest_message": {
        "ID": 1,
        "sender_id": 124,
        "message_text": "encrypted_message",
        "nonce": "nonce_string",
        "created_at": "2024-12-24 12:00:00"
      }
    }
  ]
}
```

---

### 3. Sync User Identity Keys

Set or update a user's public keys for end-to-end encryption.

**Endpoint:** `POST /identity/sync`

**Authentication:** Bearer token required

**Request Body (form-data):**
| Parameter    | Type   | Required | Description |
|--------------|--------|----------|-------------|
| user_id      | integer| Yes      | User ID |
| ik_pub_b64   | string | Yes      | Identity key public (base64) |
| sig_pub_b64  | string | Yes      | Signature key public (base64) |
| spk_pub_b64  | string | Yes      | Signed prekey public (base64) |
| spk_sig_b64  | string | Yes      | Signed prekey signature (base64) |

**Response (Success - 200):**
```json
{
  "success": true,
  "user_id": 123
}
```

**Response (Error - 400):**
```json
{
  "code": "invalid_params",
  "message": "Missing required parameters.",
  "data": { "status": 400 }
}
```

---

### 4. Get Users

Retrieve list of users who have set up their encryption keys.

**Endpoint:** `POST /users`

**Authentication:** Bearer token required

**Request Body:** None (user_id from auth)

**Response (Success - 200):**
```json
[
  {
    "ID": 124,
    "display_name": "Jane Smith",
    "public_key": "base64_string",
    "key_type": "identity",
    "expires_at": null
  }
]
```

---

### 5. Get Conversations

Get all conversations for the authenticated user.

**Endpoint:** `POST /conversations`

**Authentication:** Bearer token required

**Request Body:** None (user_id from auth)

**Response (Success - 200):**
```json
[
  {
    "ID": 1,
    "type": "private",
    "created_by": 123,
    "created_at": "2024-12-24 12:00:00",
    "session_key": "encrypted_key",
    "conversation_name": "",
    "members": [
      {
        "ID": 124,
        "display_name": "Jane Smith",
        "public_key": "base64_string",
        "key_type": "identity",
        "expires_at": null
      }
    ]
  }
]
```

---

### 6. Start Private Conversation

Create a new private conversation between two users.

**Endpoint:** `POST /conversations/start-private`

**Authentication:** Bearer token required

**Request Body (form-data):**
| Parameter             | Type    | Required | Description |
|-----------------------|---------|----------|-------------|
| other_user_id         | integer | Yes      | ID of the other user |
| encrypted_session_key | string  | Yes      | Encrypted session key |

**Response (Success - 200):**
```json
{
  "success": true,
  "conversation_id": 1
}
```

**Response (Error - 400):**
```json
{
  "code": "invalid_params",
  "message": "Missing required parameters.",
  "data": { "status": 400 }
}
```

---

### 7. Start Group Conversation

Create a new group conversation with multiple users.

**Endpoint:** `POST /conversations/start-group`

**Authentication:** Bearer token required

**Request Body (form-data):**
| Parameter          | Type           | Required | Description |
|--------------------|----------------|----------|-------------|
| member_ids         | array/string   | Yes      | Array of user IDs or comma-separated string |
| encrypted_message  | string         | Yes      | Initial encrypted message |

**Response (Success - 200):**
```json
{
  "success": true,
  "conversation_id": 2
}
```

**Response (Error - 400):**
```json
{
  "code": "invalid_params",
  "message": "Missing required parameters.",
  "data": { "status": 400 }
}
```

---

### 8. Get Conversation Messages

Retrieve all messages for a specific conversation.

**Endpoint:** `POST /conversations/get-messages`

**Authentication:** Bearer token required

**Request Body (form-data):**
| Parameter        | Type    | Required | Description |
|------------------|---------|----------|-------------|
| conversation_id  | integer | Yes      | Conversation ID |

**Response (Success - 200):**
```json
{
  "conversation": {
    "ID": 1,
    "type": "private",
    "created_by": 123,
    "created_at": "2024-12-24 12:00:00",
    "session_key": "encrypted_key",
    "conversation_name": null
  },
  "members": [
    {
      "ID": 123,
      "display_name": "John Doe",
      "public_key": "base64_string",
      "key_type": "identity",
      "expires_at": null
    }
  ],
  "messages": [
    {
      "id": 1,
      "conversation_id": 1,
      "sender_id": 124,
      "message_text": "encrypted_message",
      "nonce": "nonce_string",
      "file_path": null,
      "created_at": "2024-12-24 12:00:00"
    }
  ]
}
```

**Response (Error - 403):**
```json
{
  "code": "not_a_member",
  "message": "You are not a member of this conversation.",
  "data": { "status": 403 }
}
```

---

### 9. Send Message

Send a message to a conversation.

**Endpoint:** `POST /conversations/send-message`

**Authentication:** Bearer token required

**URL Parameter:**
- `conversation_id` (integer): The conversation ID

**Request Body (form-data):**
| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| message   | string | Yes      | Encrypted message text |
| nonce     | string | Yes      | Encryption nonce |

**Response (Success - 200):**
```json
{
  "success": true,
  "message_id": 2
}
```

**Response (Error - 403):**
```json
{
  "code": "not_a_member",
  "message": "You are not a member of this conversation.",
  "data": { "status": 403 }
}
```

---

## Error Codes

| Code              | Status | Description |
|-------------------|--------|-------------|
| invalid_login     | 401    | Invalid username or password |
| no_token          | 401    | Access token not provided |
| invalid_request   | 401    | Invalid or expired token |
| no_user           | 401    | User ID not provided |
| invalid_params    | 400    | Missing or invalid parameters |
| invalid_user      | 400    | Specified user does not exist |
| not_a_member      | 403    | User not member of conversation |
| db_error          | 500    | Database operation failed |

## Security Notes

- All messages are encrypted client-side before transmission
- Private keys are never stored on the server
- Access tokens are hashed and have configurable expiration
- All endpoints use POST to prevent logging of sensitive data in server logs
- Authentication requires both Bearer token and user_id for performance

## Database Tables

The plugin creates the following tables:
- `bh_access_tokens` - User authentication tokens
- `bh_conversations` - Conversation metadata
- `bh_conversation_members` - Conversation membership
- `bh_messages` - Encrypted messages
- `bh_user_keys` - User public keys
- `bh_conversation_keys` - Encrypted conversation keys</content>
<parameter name="filePath">c:\Program Files\Ampps\www\sites\blackhaven.local\wp-content\plugins\blackhaven-messenger\API_DOCUMENTATION.md