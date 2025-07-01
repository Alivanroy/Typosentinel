# Multi-stage build for TypoSentinel Web Demo
FROM nginx:alpine

# Copy static files
COPY index.html /usr/share/nginx/html/
COPY styles.css /usr/share/nginx/html/
COPY script.js /usr/share/nginx/html/

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Create directory for SSL certificates (if needed)
RUN mkdir -p /etc/nginx/ssl

# Set proper permissions
RUN chmod -R 755 /usr/share/nginx/html

# Expose port 80 and 443
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]