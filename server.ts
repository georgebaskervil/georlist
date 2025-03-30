import { join } from "path";
import fs from "fs";
import { compileBlocklist } from "./compile.js";
import { fileURLToPath } from "url";
import http from "http";
import { IncomingMessage, ServerResponse } from "http";

// Configuration
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "localhost";
const FILE_PATH = join(process.cwd(), "adguard-blocklist.txt");

// Rate limiting configuration
const RATE_WINDOW_MS = 60 * 1000; // 1 minute window
const MAX_REQUESTS_PER_WINDOW = 30; // 30 requests per minute
const ipRequestCounts = new Map<string, { count: number; resetTime: number }>();

/**
 * Simple rate limiter to prevent abuse
 */
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const requestData = ipRequestCounts.get(ip) || { count: 0, resetTime: now + RATE_WINDOW_MS };
  
  // Reset counter if window expired
  if (now > requestData.resetTime) {
    requestData.count = 1;
    requestData.resetTime = now + RATE_WINDOW_MS;
  } else {
    requestData.count += 1;
  }
  
  ipRequestCounts.set(ip, requestData);
  
  // Clean up old entries periodically (every 100 requests)
  if (Math.random() < 0.01) {
    for (const [storedIp, data] of ipRequestCounts.entries()) {
      if (now > data.resetTime) {
        ipRequestCounts.delete(storedIp);
      }
    }
  }
  
  return requestData.count > MAX_REQUESTS_PER_WINDOW;
}

/**
 * Validate the path to prevent path traversal attacks
 */
function isValidPath(path: string): boolean {
  // Prevent path traversal by normalizing and comparing paths
  const normalizedPath = join(process.cwd(), path);
  return normalizedPath === FILE_PATH;
}

/**
 * Main server function
 */
async function startServer() {
  console.log(`Starting AdGuard blocklist server on ${HOST}:${PORT}...`);
  
  // Ensure the blocklist file exists
  if (!fs.existsSync(FILE_PATH)) {
    console.log("Blocklist file not found. Compiling now...");
    await compileBlocklist();
  } else {
    console.log(`Using existing blocklist file: ${FILE_PATH}`);
  }
  
  // Create server
  const server = http.createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || "unknown";
      
      // Apply rate limiting
      if (isRateLimited(clientIp)) {
        res.statusCode = 429;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Retry-After", "60");
        res.end("Too Many Requests");
        return;
      }
      
      const url = new URL(req.url || "/", `http://${req.headers.host}`);
      
      // Security check: Only allow GET requests
      if (req.method !== "GET") {
        res.statusCode = 405;
        res.end("Method Not Allowed");
        return;
      }
      
      // Serve the blocklist at the root path or /blocklist.txt
      if (url.pathname === "/" || url.pathname === "/blocklist.txt") {
        // Validate the file path is correct
        if (!isValidPath("adguard-blocklist.txt")) {
          res.statusCode = 500;
          res.end("Internal Server Error");
          return;
        }
        
        // Security check: Ensure file exists
        if (!fs.existsSync(FILE_PATH)) {
          res.statusCode = 404;
          res.end("Blocklist not found");
          return;
        }
        
        // Get the last modification time of the file
        const stats = fs.statSync(FILE_PATH);
        const lastModified = stats.mtime.toUTCString();
        
        // If-Modified-Since header check
        const ifModifiedSince = req.headers["if-modified-since"];
        if (ifModifiedSince && new Date(ifModifiedSince) >= stats.mtime) {
          res.statusCode = 304; // Not Modified
          res.end();
          return;
        }
        
        // Serve the file with appropriate security headers
        const fileContent = fs.readFileSync(FILE_PATH, "utf-8");
        
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Last-Modified", lastModified);
        res.setHeader("Cache-Control", "public, max-age=3600");
        res.setHeader("Content-Length", Buffer.byteLength(fileContent, "utf-8"));
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Content-Security-Policy", "default-src 'none'");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
        res.end(fileContent);
        return;
      }
      
      // Secured health check endpoint (only accessible from localhost or Docker network)
      if (url.pathname === "/health") {
        // Allow access only from localhost or internal Docker network
        const host = req.headers.host || "";
        if (host.includes("localhost") || host.includes("127.0.0.1") || 
            (clientIp && (clientIp.startsWith("172.") || clientIp.startsWith("192.168.")))) {
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.setHeader("X-Content-Type-Options", "nosniff");
          res.end(JSON.stringify({ status: "ok" }));
          return;
        } else {
          // Pretend the endpoint doesn't exist for external users
          res.statusCode = 404;
          res.end("Not Found");
          return;
        }
      }
      
      // Not found for any other routes
      res.statusCode = 404;
      res.end("Not Found");
    } catch (error) {
      // Log the error but don't expose details to the client
      console.error("Server error:", error);
      res.statusCode = 500;
      res.end("Internal Server Error");
    }
  });
  
  // Start listening
  server.listen(PORT, HOST, () => {
    console.log(`Server started at http://${HOST}:${PORT}`);
    console.log(`Blocklist available at http://${HOST}:${PORT}/blocklist.txt`);
  });
  
  // Return the server instance
  return server;
}

// Start the server if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
}

export default startServer; 