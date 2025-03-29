import { join } from "path";
import fs from "fs";
import { compileBlocklist } from "./compile";
import { fileURLToPath } from "url";

// Configuration
const PORT = process.env.PORT || 3000;
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
  const server = Bun.serve({
    port: PORT,
    hostname: HOST,
    async fetch(req) {
      try {
        const clientIp = req.headers.get("x-forwarded-for") || "unknown";
        
        // Apply rate limiting
        if (isRateLimited(clientIp)) {
          return new Response("Too Many Requests", { 
            status: 429,
            headers: {
              "Content-Type": "text/plain; charset=utf-8",
              "Retry-After": "60",
            }
          });
        }
        
        const url = new URL(req.url);
        
        // Security check: Only allow GET requests
        if (req.method !== "GET") {
          return new Response("Method Not Allowed", { status: 405 });
        }
        
        // Serve the blocklist at the root path or /blocklist.txt
        if (url.pathname === "/" || url.pathname === "/blocklist.txt") {
          // Validate the file path is correct
          if (!isValidPath("adguard-blocklist.txt")) {
            return new Response("Internal Server Error", { status: 500 });
          }
          
          // Security check: Ensure file exists
          if (!fs.existsSync(FILE_PATH)) {
            return new Response("Blocklist not found", { status: 404 });
          }
          
          // Get the last modification time of the file
          const stats = fs.statSync(FILE_PATH);
          const lastModified = stats.mtime.toUTCString();
          
          // If-Modified-Since header check
          const ifModifiedSince = req.headers.get("If-Modified-Since");
          if (ifModifiedSince && new Date(ifModifiedSince) >= stats.mtime) {
            return new Response(null, { status: 304 }); // Not Modified
          }
          
          // Serve the file with appropriate security headers
          const fileContent = fs.readFileSync(FILE_PATH, "utf-8");
          return new Response(fileContent, {
            headers: {
              "Content-Type": "text/plain; charset=utf-8",
              "Last-Modified": lastModified,
              "Cache-Control": "public, max-age=3600",
              "Content-Length": String(Buffer.byteLength(fileContent, "utf-8")),
              "X-Content-Type-Options": "nosniff",
              "X-Frame-Options": "DENY",
              "Content-Security-Policy": "default-src 'none'",
              "Referrer-Policy": "no-referrer",
              "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"
            },
          });
        }
        
        // Secured health check endpoint (only accessible from localhost or Docker network)
        if (url.pathname === "/health") {
          // Allow access only from localhost or internal Docker network
          const host = req.headers.get("host") || "";
          if (host.includes("localhost") || host.includes("127.0.0.1") || clientIp.startsWith("172.") || clientIp.startsWith("192.168.")) {
            return new Response(JSON.stringify({ status: "ok" }), {
              headers: { 
                "Content-Type": "application/json",
                "X-Content-Type-Options": "nosniff"
              },
            });
          } else {
            // Pretend the endpoint doesn't exist for external users
            return new Response("Not Found", { status: 404 });
          }
        }
        
        // Not found for any other routes
        return new Response("Not Found", { status: 404 });
      } catch (error) {
        // Log the error but don't expose details to the client
        console.error("Server error:", error);
        return new Response("Internal Server Error", { status: 500 });
      }
    },
  });
  
  console.log(`Server started at http://${server.hostname}:${server.port}`);
  console.log(`Blocklist available at http://${server.hostname}:${server.port}/blocklist.txt`);
}

// Start the server if this file is executed directly
if (import.meta.main) {
  startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
  });
}

export default startServer; 