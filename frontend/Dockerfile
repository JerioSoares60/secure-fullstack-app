# Simple frontend Dockerfile
FROM nginx:alpine

# Install security updates
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy the HTML file
COPY index.html /usr/share/nginx/html/index.html

# Create necessary directories
RUN mkdir -p /var/cache/nginx /var/log/nginx /etc/nginx/conf.d

# Remove default nginx configuration
RUN rm -f /etc/nginx/conf.d/default.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
