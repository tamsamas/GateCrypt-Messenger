# Chat App API Documentation

## Base URL
```
https://localhost:8443
```

## Authentication
Most endpoints require a JWT token. Include it in the request header:
```
Authorization: Bearer <token>
```

---

## Endpoints

### Public Endpoints

#### 1. Get MOTD
```
GET /motd
```
Returns the message of the day.

**Response:**
```json
{
  "motd": "Welcome"
}
```

---

#### 2. Get Version
```
GET /version
```
Returns the current server version.

**Response:**
```json
{
  "ver": "1.4.03"
}
```

---

#### 3. Register User
```
POST /register
```
Create a new user account using an invite code.

**Request Body:**
```json
{
  "username": "string (max 20 characters)",
  "password": "string (min 8 characters)",
  "invite_code": "string"
}
```

**Response:**
```json
{
  "user_id": "integer"
}
```

**Error Responses:**
- `400`: Missing fields, invalid invite code, username too long, or password too short
- `429`: Too many registration attempts (blocks for 10 minutes after 20 attempts in 5 seconds)

**Rate Limiting:** Maximum 20 attempts per 5 seconds per IP, then 10-minute block.

---

#### 4. Login
```
POST /login
```
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response:**
```json
{
  "token": "jwt_token"
}
```

**Error Responses:**
- `400`: Missing fields or invalid credentials
- `429`: Too many login attempts (blocks for 15 minutes after 10 failed attempts)

**Rate Limiting:** Maximum 10 failed attempts per 60 seconds per IP/username, then 15-minute block.

---

#### 5. Get Username by ID
```
GET /username/:id
```
Get the username of a user by their ID.

**Response:**
```json
{
  "username": "string"
}
```

**Error Responses:**
- `404`: User not found

---

#### 6. Get Profile Picture
```
GET /getpfp
```
Retrieve a user's profile picture.

**Query Parameters:**
- `id` (required): User ID

**Response:**
```json
{
  "profile_picture": "base64_string or false"
}
```

**Error Responses:**
- `400`: Missing id query parameter
- `404`: User not found

---

### Authenticated Endpoints (Require JWT Token)

#### 7. Get Current User Info
```
GET /me
```
Get information about the currently authenticated user.

**Response:**
```json
{
  "id": "integer",
  "username": "string"
}
```

**Error Responses:**
- `401`: No token or invalid token
- `404`: User not found

---

#### 8. Create Invite Code
```
POST /invites
```
Generate a new invite code for registering other users.

**Response:**
```json
{
  "invite_code": "string"
}
```

**Rules:**
- **Admin/Tester roles:** Can create unlimited invites
- **Regular users:** 
  - Can only have one active invite at a time
  - Must wait 24 hours between creating invites
  - First invite: No chat requirement
  - Second invite: Must have chatted with 1+ unique users
  - Third invite: Must have chatted with 2+ unique users
  - Fourth+ invite: Must have chatted with 5+ unique users

**Error Responses:**
- `401`: No token or invalid token
- `403`: Already have active invite, cooldown period active, or insufficient chat partners
- `404`: User not found
- `500`: Server error

---

#### 9. Start/Reset Conversation
```
GET /conversation/start
```
Initialize or reset a conversation with another user. Generates a new AES-256 encryption key.

**Query Parameters:**
- `user_id` (required): ID of the other user

**Response:**
```json
{
  "aes_key": "base64_string",
  "reset": "boolean"
}
```

**Details:**
- `reset: true` - Existing conversation was reset with new key
- `reset: false` - New conversation created
- Deletes all previous messages in the conversation
- Creates pending keys for both users

**Error Responses:**
- `400`: Missing user_id query parameter
- `401`: No token or invalid token

---

#### 10. Check for New Encryption Key
```
GET /conversation/check-key
```
Check if a new encryption key is pending for a conversation.

**Query Parameters:**
- `user_id` (required): ID of the other user

**Response:**
```json
{
  "new_key": "boolean",
  "aes_key": "base64_string (optional)"
}
```

**Error Responses:**
- `400`: Missing user_id query parameter
- `401`: No token or invalid token

---

#### 11. Send Message
```
POST /messages
```
Send an encrypted message to another user.

**Request Body:**
```json
{
  "receiver_id": "integer",
  "message": "string (max 700000 characters)"
}
```

**Response:**
```json
{
  "message_id": "integer"
}
```

**Rate Limiting:** Maximum 8 messages per 10 seconds per user.

**Error Responses:**
- `400`: Missing fields or message too long
- `401`: No token or invalid token
- `429`: Rate limit exceeded (max 8 messages per 10 seconds)

---

#### 12. Get Messages (Paginated)
```
GET /messages
```
Retrieve messages between the authenticated user and another user (paginated).

**Query Parameters:**
- `user_id` (required): ID of the other user
- `page` (optional): Page number (default: 1, 50 messages per page)

**Response:**
```json
[
  {
    "id": "integer",
    "sender_id": "integer",
    "sender_username": "string",
    "receiver_id": "integer",
    "receiver_username": "string",
    "message": "string",
    "timestamp": "string (formatted local time)"
  }
]
```

**Error Responses:**
- `400`: Missing user_id query parameter
- `401`: No token or invalid token

---

#### 13. Get All Messages
```
GET /allmessages
```
Retrieve all messages between the authenticated user and another user (unfiltered).

**Query Parameters:**
- `user_id` (required): ID of the other user

**Response:**
```json
[
  {
    "id": "integer",
    "sender_id": "integer",
    "sender_username": "string",
    "receiver_id": "integer",
    "receiver_username": "string",
    "message": "string",
    "timestamp": "string (formatted local time)"
  }
]
```

**Error Responses:**
- `400`: Missing user_id query parameter
- `401`: No token or invalid token

---

#### 14. Check for New Messages
```
GET /messages/updates
```
Check for new messages received since last check and get notification text.

**Response:**
```json
{
  "notification_data": "string",
  "all_messages": "integer"
}
```

**Examples:**
- `"notification_data": "Alice sent you a new message"`
- `"notification_data": "Alice and Bob sent you a new message"`
- `"notification_data": "Alice, Bob, and Charlie sent you a new message"`

**Details:**
- Tracks last seen message ID per user
- Returns empty notification if no new messages

**Error Responses:**
- `401`: No token or invalid token

---

#### 15. Get New Messages List
```
GET /messages/newmessages
```
Get a list of all users who have sent messages to the authenticated user.

**Response:**
```json
{
  "updates": [
    {
      "sender_id": "integer",
      "username": "string"
    }
  ]
}
```

**Details:**
- Returns one entry per unique sender (ordered by latest message)
- Empty array if no messages received

**Error Responses:**
- `401`: No token or invalid token

---

#### 16. Upload Profile Picture
```
POST /uploadpfp
```
Upload a 256x256 pixel profile picture.

**Request Body:**
```json
{
  "image": "data:image/png;base64,<base64_encoded_image>"
}
```

**Requirements:**
- Must be exactly 256x256 pixels
- Supported formats: PNG, JPEG, etc.
- Stored as base64 in database

**Response:**
```json
{
  "success": true
}
```

**Error Responses:**
- `400`: Invalid image (wrong dimensions or invalid format)
- `401`: No token or invalid token

---

## Database Schema

### users
- `id` - Primary key
- `username` - Unique username (max 20 characters)
- `password_hash` - Bcrypt hashed password
- `role` - User role (user, admin, tester)
- `invited_by` - ID of user who invited them
- `created_at` - Account creation timestamp
- `profile_picture` - Base64 encoded 256x256 image
- `last_seen_msg_id` - Last message ID seen by this user

### messages
- `id` - Primary key
- `sender_id` - Foreign key to users
- `receiver_id` - Foreign key to users
- `message` - Message content (up to 700000 characters)
- `timestamp` - Creation timestamp

### invites
- `id` - Primary key
- `code` - Unique 8-character hex code
- `created_by` - Foreign key to users
- `used_by` - Foreign key to users (null if unused)
- `created_at` - Creation timestamp
- `used_at` - Usage timestamp (null if unused)

### conversations
- `id` - Primary key
- `user1_id` - Foreign key to users
- `user2_id` - Foreign key to users
- `aes_key` - Current AES-256 encryption key (base64)

### pending_keys
- `id` - Primary key
- `conversation_id` - Foreign key to conversations
- `user_id` - Foreign key to users
- `aes_key` - AES-256 encryption key for this user
- `delivered` - Whether key has been delivered

---

## Error Handling

All error responses follow this format:
```json
{
  "error": "error message"
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad request (missing fields, invalid data)
- `401` - Unauthorized (missing or invalid token)
- `403` - Forbidden (insufficient permissions or limits exceeded)
- `404` - Not found (user or resource doesn't exist)
- `429` - Too many requests (rate limited)
- `500` - Server error

---

## Security Features

- **JWT Authentication:** All protected endpoints use JWT tokens with 1-day expiration
- **Password Hashing:** Bcrypt with salt rounds of 10
- **Rate Limiting:** 
  - Login: 10 attempts per 60 seconds
  - Registration: 20 attempts per 5 seconds
  - Messages: 8 per 10 seconds
- **Encryption:** AES-256 keys generated per conversation
- **Timing Attack Protection:** Uses dummy password hash for non-existent users during login
- **SQL Injection Protection:** Parameterized queries throughout
