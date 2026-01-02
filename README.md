# Server Auth

An authentication proxy server written in Go that provides login-based access control and reverse proxying to a backend service.

## Features

- **Authentication System**: Secure login with bcrypt password hashing
- **Token-based Sessions**: JWT-like tokens stored in HTTP-only cookies
- **User Management**: Admin interface to create and delete users
- **Reverse Proxy**: Proxies authenticated requests to a backend localhost port
- **Persistent Storage**: User data stored in JSON file (`users.json`)
- **Default Credentials**: Root user created automatically (username: `root`, password: `root`)

## Installation

```bash
go mod download
go build -o server-auth
```

## Usage

```bash
# Start server on port 8080, proxying to localhost:3000
./server-auth -port 8080 -proxy 3000

# Or using go run
go run main.go -port 8080 -proxy 3000
```

### Command-line Arguments

- `-port`: Server port (default: 8080)
- `-proxy`: Backend port to proxy authenticated requests to (default: 3000)

## Endpoints

- `GET /login` - Login page
- `POST /api/login` - Login API (JSON: `{"username": "...", "password": "..."}`)
- `POST /api/logout` - Logout and invalidate session
- `GET /admin` - Admin user management interface (requires authentication)
- `GET /api/admin/users` - List all users (requires authentication)
- `POST /api/admin/users` - Create new user (requires authentication)
- `DELETE /api/admin/users` - Delete user (requires authentication)
- `/*` - All other paths are proxied to the backend after authentication

## Security Features

- Passwords stored using bcrypt hashing
- HTTP-only cookies to prevent XSS attacks
- Session expiration (7 days)
- Root user cannot be deleted
- File permissions set to 0600 for user data

## Example Workflow

1. Start your backend service on a port (e.g., port 3000)
2. Start the auth server: `./server-auth -proxy 3000`
3. Navigate to `http://localhost:8080`
4. Login with username: `root`, password: `root`
5. Access your backend through the authenticated proxy
6. Manage users at `http://localhost:8080/admin`

## Data Storage

User data is stored in `users.json` in the working directory with the following structure:

```json
{
  "root": {
    "username": "root",
    "password_hash": "$2a$10$..."
  }
}
```