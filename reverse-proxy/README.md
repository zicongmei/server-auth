# HTTPS Reverse Proxy with Let's Encrypt

A Go-based HTTPS reverse proxy that provides authentication and a user management interface.

## Features

- HTTPS using Let's Encrypt (`autocert`).
- Per-IP rate limiting on the login page (5 requests per minute).
- Authentication required for all proxied requests.
- Admin interface at `/admin` to manage users (create, update, change password, delete).
- Configurable initial admin account.
- Passwords stored as bcrypt hashes in `users.json`.

## Requirements

- Domain name pointing to the server.
- Port 80 and 443 must be open and available.

## How to Build

### Using Go directly
```bash
go build -o reverse-proxy main.go
```

### Using Makefile
```bash
make build
```

### Building Docker Image
```bash
make docker-build
```

## How to Run

### Running locally
Running the binary requires root privileges to bind to ports 80 and 443.

```bash
sudo ./reverse-proxy -hostname yourdomain.com -proxy-port 3000 -admin-username admin -admin-password your_secret_password
```

### Running with Docker
To run the proxy in detached mode, mapping ports 80 and 443, and mounting a data directory from your host:

```bash
docker run -d \
  --name reverse-proxy \
  -p 80:80 \
  -p 443:443 \
  -v /absolute/path/to/host/data:/app/data \
  zicongmei/reverse-proxy:latest \
  -hostname yourdomain.com -proxy-port 3128 -admin-username admin -admin-password your_secret_password
```

### Flags

- `-hostname`: The host name of this server (required for Let's Encrypt).
- `-proxy-port`: The localhost port to redirect authenticated traffic to (default: 3000).
- `-port`: The port this server listens on (default: 443).
- `-data-dir`: Directory to store `users.json` and certificates (default: ".").
- `-admin-username`: Initial admin username (required ONLY if `users.json` is missing).
- `-admin-password`: Initial admin password (required ONLY if `users.json` is missing).

## Docker Hub

To push the image to Docker Hub (default account: `zicongmei`):
```bash
make push
```

## Admin Interface

Navigate to `https://yourdomain.com/admin` to manage users.
Default credentials:
- Username: `root`
- Password: `root`

**Note:** It is highly recommended to change the root password immediately after first login.