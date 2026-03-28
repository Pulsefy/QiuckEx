# Public Profile Discovery - API Quick Reference

## Base URL
```
http://localhost:3000/username
```

---

## Endpoints

### 1. Search Public Profiles

**GET** `/username/search`

Fuzzy search for public profiles with similarity scoring.

#### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `query` | string | ✅ Yes | - | Search term (min 2 chars) |
| `limit` | number | ❌ No | 10 | Max results (1-100) |

#### Example Request

```bash
curl "http://localhost:3000/username/search?query=alice&limit=10"
```

#### Example Response

```json
{
  "profiles": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "username": "alice",
      "publicKey": "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
      "similarityScore": 95,
      "lastActiveAt": "2025-03-27T10:30:00Z",
      "createdAt": "2025-02-19T08:00:00Z"
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "username": "alicen",
      "publicKey": "GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS",
      "similarityScore": 85,
      "lastActiveAt": "2025-03-26T15:20:00Z",
      "createdAt": "2025-02-20T09:15:00Z"
    }
  ],
  "total": 2
}
```

#### Status Codes

- `200 OK` - Success
- `400 Bad Request` - Invalid query (too short or invalid format)

---

### 2. Get Trending Creators

**GET** `/username/trending`

Get trending creator profiles ranked by transaction volume.

#### Parameters

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `timeWindowHours` | number | ❌ No | 24 | Time window (1-720 hours) |
| `limit` | number | ❌ No | 10 | Max creators (1-100) |

#### Example Request

```bash
curl "http://localhost:3000/username/trending?timeWindowHours=24&limit=10"
```

#### Example Response

```json
{
  "creators": [
    {
      "id": "770e8400-e29b-41d4-a716-446655440002",
      "username": "toptrader",
      "publicKey": "GDXYZ123ABC456DEF789GHI012JKL345MNO678PQR901STU",
      "transactionVolume": 75000.50,
      "transactionCount": 200,
      "lastActiveAt": "2025-03-27T11:45:00Z",
      "createdAt": "2025-02-19T08:00:00Z"
    },
    {
      "id": "880e8400-e29b-41d4-a716-446655440003",
      "username": "activeuser",
      "publicKey": "GEABC456DEF789GHI012JKL345MNO678PQR901STU234VWX",
      "transactionVolume": 35250.75,
      "transactionCount": 95,
      "lastActiveAt": "2025-03-27T09:30:00Z",
      "createdAt": "2025-02-20T10:00:00Z"
    }
  ],
  "timeWindowHours": 24,
  "calculatedAt": "2025-03-27T12:00:00Z"
}
```

#### Status Codes

- `200 OK` - Success
- `400 Bad Request` - Invalid time window parameter

---

### 3. Toggle Public Profile Visibility

**POST** `/username/toggle-public`

Enable or disable public profile visibility.

#### Request Body

```json
{
  "username": "alice",
  "publicKey": "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
  "isPublic": true
}
```

#### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `username` | string | ✅ Yes | Username to toggle |
| `publicKey` | string | ✅ Yes | Owner's Stellar public key |
| `isPublic` | boolean | ✅ Yes | Visibility state |

#### Example Request

```bash
curl -X POST "http://localhost:3000/username/toggle-public" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "publicKey": "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
    "isPublic": true
  }'
```

#### Example Response (Success)

```json
{
  "ok": true
}
```

#### Status Codes

- `200 OK` - Successfully toggled
- `400 Bad Request` - Invalid username format
- `404 Not Found` - Username not found or wrong ownership
- `500 Internal Server Error` - Server error

---

## Field Descriptions

### PublicProfile Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique identifier |
| `username` | string | Normalized username (lowercase) |
| `publicKey` | string | Stellar public key (G...) |
| `similarityScore` | number | Search relevance (0-100), only in search results |
| `transactionVolume` | number | Total USD volume, only in trending results |
| `transactionCount` | number | Number of transactions, only in trending results |
| `lastActiveAt` | ISO 8601 datetime | Last activity timestamp |
| `createdAt` | ISO 8601 datetime | Registration timestamp |

---

## Usage Notes

### Search Tips
- Minimum 2 characters required
- Case-insensitive (automatically normalized)
- Supports partial matches and typos
- Results ranked by similarity score
- Only includes profiles with `is_public=true`

### Trending Algorithm
- Based on actual payment transaction volume
- Counts both sender and receiver activity
- Volume measured in USD
- Only public profiles appear in results
- Real-time calculation (no caching)

### Privacy Controls
- Profiles are **private by default** (opt-in)
- Only wallet owners can toggle visibility
- Changes take effect immediately
- Hidden profiles won't appear in search or trending

---

## Rate Limits

All endpoints are subject to rate limiting:
- Default: 10 requests/minute
- With API key: Higher limits apply
- Exceeding limits returns `429 Too Many Requests`

---

## Error Responses

### 400 Bad Request
```json
{
  "code": "USERNAME_INVALID_FORMAT",
  "message": "Search query must be at least 2 characters",
  "field": "query"
}
```

### 404 Not Found
```json
{
  "code": "USERNAME_NOT_FOUND",
  "message": "Username not found or does not belong to this wallet"
}
```

### 429 Too Many Requests
```json
{
  "statusCode": 429,
  "error": "Too Many Requests",
  "message": "Rate limit exceeded"
}
```

---

## Swagger Documentation

Interactive API documentation available at:
```
http://localhost:3000/api#/usernames
```

Features:
- Try it out directly in browser
- See all request/response schemas
- Download OpenAPI spec

---

## Code Examples

### JavaScript/Node.js

```javascript
// Search for profiles
async function searchProfiles(query, limit = 10) {
  const response = await fetch(
    `http://localhost:3000/username/search?query=${query}&limit=${limit}`
  );
  return await response.json();
}

// Get trending creators
async function getTrendingCreators(timeWindowHours = 24, limit = 10) {
  const response = await fetch(
    `http://localhost:3000/username/trending?timeWindowHours=${timeWindowHours}&limit=${limit}`
  );
  return await response.json();
}

// Toggle public profile
async function togglePublicProfile(username, publicKey, isPublic) {
  const response = await fetch(
    'http://localhost:3000/username/toggle-public',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, publicKey, isPublic }),
    }
  );
  return await response.json();
}
```

### Python

```python
import requests

BASE_URL = "http://localhost:3000"

def search_profiles(query, limit=10):
    response = requests.get(
        f"{BASE_URL}/username/search",
        params={"query": query, "limit": limit}
    )
    return response.json()

def get_trending_creators(time_window_hours=24, limit=10):
    response = requests.get(
        f"{BASE_URL}/username/trending",
        params={"timeWindowHours": time_window_hours, "limit": limit}
    )
    return response.json()

def toggle_public_profile(username, public_key, is_public):
    response = requests.post(
        f"{BASE_URL}/username/toggle-public",
        json={"username": username, "publicKey": public_key, "isPublic": is_public}
    )
    return response.json()
```

### cURL Examples

```bash
# Search
curl "http://localhost:3000/username/search?query=alice&limit=5"

# Trending (last 7 days)
curl "http://localhost:3000/username/trending?timeWindowHours=168&limit=20"

# Enable public profile
curl -X POST "http://localhost:3000/username/toggle-public" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","publicKey":"GBXG...","isPublic":true}'

# Disable public profile
curl -X POST "http://localhost:3000/username/toggle-public" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","publicKey":"GBXG...","isPublic":false}'
```

---

**Last Updated:** March 27, 2025  
**Version:** 1.0.0
