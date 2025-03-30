# Use Node.js Alpine as the base image
FROM node:20-alpine AS base

# Set working directory
WORKDIR /app

# Build stage
FROM base AS builder

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM base AS runtime

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Copy production dependencies and build files
COPY --from=builder /app/package.json /app/package-lock.json* ./
RUN npm ci --omit=dev

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/config.json ./

# Create a non-root user and set permissions
RUN addgroup -g 1001 nodejs && \
    adduser -S -u 1001 -G nodejs appuser && \
    chown -R appuser:nodejs /app

# Switch to non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 3000

# Healthcheck configuration
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["node", "dist/index.js"] 