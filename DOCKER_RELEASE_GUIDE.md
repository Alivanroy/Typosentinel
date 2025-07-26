# 🐳 Docker Release Guide for Typosentinel v1.1.0

## Current Status
✅ **Docker image built successfully**: `ghcr.io/alivanroy/typosentinel:v1.1.0`  
✅ **Tagged as latest**: `ghcr.io/alivanroy/typosentinel:latest`  
✅ **Release notes updated** with Docker information  
⚠️ **Pending**: Push to GitHub Container Registry (requires proper permissions)

## 🔧 Built Images
The following Docker images are ready locally:
```bash
ghcr.io/alivanroy/typosentinel:v1.1.0
ghcr.io/alivanroy/typosentinel:latest
```

## 🚀 Pushing to GitHub Container Registry

### Option 1: Using Personal Access Token (Recommended)
1. **Create a Personal Access Token** with `write:packages` scope:
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate new token with `write:packages` permission

2. **Authenticate and Push**:
   ```bash
   # Set your token as environment variable
   export GITHUB_TOKEN="your_personal_access_token_here"
   
   # Login to GitHub Container Registry
   echo $GITHUB_TOKEN | docker login ghcr.io -u alivanroy --password-stdin
   
   # Push the versioned image
   docker push ghcr.io/alivanroy/typosentinel:v1.1.0
   
   # Push the latest tag
   docker push ghcr.io/alivanroy/typosentinel:latest
   ```

### Option 2: Using the Docker Release Script
```bash
# Run the automated script
./docker-release.sh v1.1.0
```

## 🔍 Verification
After pushing, verify the image is available:
```bash
# Pull and test the image
docker pull ghcr.io/alivanroy/typosentinel:v1.1.0
docker run -p 8080:8080 ghcr.io/alivanroy/typosentinel:v1.1.0
```

## 📦 Image Details
- **Base Image**: Alpine Linux (minimal and secure)
- **Architecture**: linux/amd64
- **Size**: ~50MB (optimized multi-stage build)
- **Security**: Non-root user, minimal attack surface
- **Port**: 8080

## 🐳 Usage Examples

### Basic Usage
```bash
docker run -p 8080:8080 ghcr.io/alivanroy/typosentinel:v1.1.0
```

### With Volume Mounting
```bash
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  ghcr.io/alivanroy/typosentinel:v1.1.0
```

### Docker Compose
```yaml
version: '3.8'
services:
  typosentinel:
    image: ghcr.io/alivanroy/typosentinel:v1.1.0
    ports:
      - "8080:8080"
    volumes:
      - ./config:/app/config
      - ./data:/app/data
    restart: unless-stopped
    environment:
      - LOG_LEVEL=info
```

## 🔧 Troubleshooting

### Permission Denied Error
If you get "permission_denied: The token provided does not match expected scopes":
1. Ensure your token has `write:packages` scope
2. Make sure you're using the correct username (`alivanroy`)
3. Try logging out and back in: `docker logout ghcr.io`

### Image Not Found (404)
This happens when the image hasn't been pushed yet. Follow the pushing steps above.

## 📋 Next Steps
1. **Push the Docker image** using one of the methods above
2. **Test the published image** by pulling it from a different machine
3. **Update CI/CD pipeline** to automatically build and push Docker images on releases
4. **Consider multi-architecture builds** for ARM64 support

## 🔗 Useful Commands
```bash
# List local images
docker images | grep typosentinel

# Check image details
docker inspect ghcr.io/alivanroy/typosentinel:v1.1.0

# Remove local images (if needed)
docker rmi ghcr.io/alivanroy/typosentinel:v1.1.0
docker rmi ghcr.io/alivanroy/typosentinel:latest
```