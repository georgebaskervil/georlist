FROM oven/bun:1.2.5 AS builder

WORKDIR /app

# Copy package files and install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy application files
COPY *.ts *.json ./

# Build the application
RUN bun run build

FROM oven/bun:1.2.5-slim

WORKDIR /app

# Install security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy only production dependencies
COPY --from=builder /app/package.json /app/bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy built application
COPY --from=builder /app/dist ./dist

# Create volume with explicit permissions
RUN mkdir -p /app/data && chmod 750 /app/data
VOLUME /app/data

# Create and use non-root user
RUN adduser --disabled-password --gecos "" --home /app appuser && \
    chown -R appuser:appuser /app

# Set proper file permissions
RUN find /app -type d -exec chmod 750 {} \; && \
    find /app -type f -exec chmod 640 {} \; && \
    find /app -type f -name "*.js" -exec chmod 750 {} \;

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Set file and directory permission umask
RUN echo "umask 027" >> ~/.profile

# Expose the web server port (documentation only)
EXPOSE 3000

# Set environment variables at runtime using --env
ENV PORT=3000 \
    HOST=127.0.0.1 \
    CRON_SCHEDULE="0 0 * * *" \
    NODE_ENV=production

# Run the application
CMD ["bun", "run", "start"] 