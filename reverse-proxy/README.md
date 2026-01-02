# HTTPS Reverse Proxy with Let's Encrypt

A Go-based HTTPS reverse proxy that provides authentication and a user management interface.

## Features

- HTTPS using Let's Encrypt (`autocert`).
- Authentication required for all proxied requests.
- Admin interface at `/admin` to manage users (create, update, change password, delete).
- Default user `root` with password `root`.
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
sudo ./reverse-proxy -hostname yourdomain.com -proxy-port 3000
```

### Running with Docker
```bash
docker run -d \
  --name reverse-proxy \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/data:/app/data \
  zicongmei/reverse-proxy:latest \
  -hostname yourdomain.com -proxy-port 3000
```

### Flags

- `-hostname`: The host name of this server (required for Let's Encrypt).
- `-proxy-port`: The localhost port to redirect authenticated traffic to (default: 3000).
- `-port`: The port this server listens on (default: 443).
- `-data-dir`: Directory to store `users.json` and certificates (default: ".").

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