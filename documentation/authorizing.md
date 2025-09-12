# Authorization Endpoint Documentation

This endpoint is used to authenticate a user and obtain an access token for subsequent requests. It allows users to log in to the application by providing their credentials.

## Request

- **Method:** `POST`
- **URL:** `https:/.<wordpress_url>/wp-json/blackhaven-messenger/v1/authorize`

### Request Body

Send the request body as `form-data` with the following parameters:

| Parameter | Type | Description                              |
|-----------|------|------------------------------------------|
| username  | text | The username of the user attempting to log in. |
| password  | text | The password associated with the provided username. |

### Response

On successful login, the server responds with a JSON object:
| Field       | Type   | Description                                                                                                                |
|-----------------|------------|--------------------------------------------------------------------------------------------------------------------|
| `success`       | boolean    | Indicates if the login was successful (`true` for success).                                                        |
| `token`         | string     | Authentication token for future requests. **Store securely.**                                                      |
| `refresh_token` | string     | Token used to re-authenticate without a full login.                                                                |
| `expires`       | string     | Expiration time of the token.<br>Example: `"2025-09-08 21:03:34"`                                                  |
| `created_at`    | string     | Timestamp when the token was generated.<br>Example: `"2024-06-10 18:45:12"`                                        |
| `user_data`     | object     | Contains user information:<br><br>```{ "ID": 123, "display_name": "John Doe" }```                                  |

### Example Response

```json
{
    "success": true,
    "token": "<access_token>",
    "refresh_token": "<refresh_token>",
    "expires": "2025-09-08 21:03:34",
    "created_at": "2024-06-10 18:45:12"
    ,
        "user_data": {
            "ID": 3746583,
            "display_name": "John Doe"
        }
}
```

## Adding an identity key to the system

Once a user is authorized, it is the clients responisbility to generate a public identify key. Once the key is created, it would be sent to the server to be stored. The public key will be used by other users to encrypt/decrypt messages with each other. 

The plugin exposes an endpoint to add a identify key to the server:

- **Method:** `POST`
- **URL:** `https:/.<wordpress_url>/wp-json/blackhaven-messenger/v1/keys/add`

### Request Body

 Send a request body as `form-data` with the following parameters:

| Parameter   | Type   | Description                                      |
|-------------|--------|--------------------------------------------------|
| user_id     | text   | The ID of the user adding the identity key.      |
| public_key  | text   | The public identity key to be stored.            |
| key_type    | text   | The type of key being added (e.g., `"identity"`).|

### Response

| Field        | Type    | Description                                         |
|--------------|---------|-----------------------------------------------------|
| `success`    | boolean | Indicates if the key was added successfully.        |
| `user_id`    | integer | The ID of the user who added the identity key.      |
| `public_key` | string  | The public identity key that was stored.            |
| `key_type`   | string  | The type of key added (e.g., `"identity"`).         |
| `expires_at` | null    | Expiration time of the key, if applicable.          |

## Usage

- Provide valid credentials in the request.
- On success, store the token securely for future authenticated API requests.

## Note

- The token is only returned once. If lost, it cannot be recovered; generate a new token if needed.
- **Do not send credentials in the URL.** Always use the request body, as proxies and web servers may log full URLs.