import { join } from "path";
import fs from "fs";
import path from "path";
import { startScheduler } from "./cron";
import startServer from "./server";
import { compileBlocklist } from "./compile";

// Configuration
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "localhost";
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || "0 0 * * *"; // Default: midnight

/**
 * Secure the path to prevent path traversal attacks
 */
function securePath(filePath: string): string {
  // Normalize the path to resolve any ../ or ./ components
  const normalizedPath = path.normalize(filePath);
  
  // Ensure the path is within the current working directory
  const resolvedPath = path.resolve(normalizedPath);
  const cwdPath = path.resolve(process.cwd());
  
  if (!resolvedPath.startsWith(cwdPath)) {
    throw new Error("Path traversal attempt detected");
  }
  
  return resolvedPath;
}

/**
 * Safely read and parse JSON from a file
 */
function safeReadJson(filePath: string): any {
  try {
    const securedPath = securePath(filePath);
    
    if (!fs.existsSync(securedPath)) {
      return null;
    }
    
    const content = fs.readFileSync(securedPath, "utf-8");
    return JSON.parse(content);
  } catch (error) {
    console.error(`Error reading JSON file ${filePath}: ${error}`);
    return null;
  }
}

/**
 * Main application entry point
 */
async function main() {
  console.log("Starting AdGuard Hostlist Compiler Application");
  
  try {
    // Process cleanup handler
    const cleanupHandler = () => {
      console.log("Shutting down application...");
      process.exit(0);
    };
    
    // Register signal handlers early
    process.on("SIGINT", cleanupHandler);
    process.on("SIGTERM", cleanupHandler);
    process.on("uncaughtException", (error) => {
      console.error("Uncaught exception:", error);
      process.exit(1);
    });
    process.on("unhandledRejection", (reason) => {
      console.error("Unhandled rejection:", reason);
      process.exit(1);
    });
    
    // Read config file
    const configPath = join(process.cwd(), "config.json");
    if (!fs.existsSync(configPath)) {
      throw new Error(`Config file not found: ${configPath}`);
    }
    
    const config = safeReadJson(configPath);
    if (!config) {
      throw new Error("Failed to parse configuration file");
    }
    
    // Check for output file and compile if needed
    const outputPath = securePath(join(process.cwd(), "adguard-blocklist.txt"));
    if (!fs.existsSync(outputPath)) {
      console.log("No existing blocklist found. Compiling initial blocklist...");
      await compileBlocklist();
    } else {
      const stats = fs.statSync(outputPath);
      const now = new Date();
      const fileAge = (now.getTime() - stats.mtime.getTime()) / 1000; // age in seconds
      
      // If file is older than a day (or specified update interval), recompile
      const updateInterval = config.updateInterval || 86400; // default: 1 day in seconds
      
      if (fileAge > updateInterval) {
        console.log(`Blocklist is older than ${updateInterval} seconds. Recompiling...`);
        await compileBlocklist();
      } else {
        console.log(`Using existing blocklist (age: ${Math.floor(fileAge)} seconds)`);
      }
    }
    
    // Start the cron scheduler for regular updates
    console.log(`Starting scheduler with schedule: ${CRON_SCHEDULE}`);
    startScheduler(CRON_SCHEDULE);
    
    // Start the web server
    await startServer();
    
    console.log("AdGuard Hostlist Compiler Application started successfully");
    console.log(`Web server: http://${HOST}:${PORT}`);
    console.log(`Scheduler: ${CRON_SCHEDULE}`);
  } catch (error) {
    console.error("Failed to start application:", error);
    process.exit(1);
  }
}

// Run the application
if (import.meta.main) {
  main().catch((error) => {
    console.error("Application failed:", error);
    process.exit(1);
  });
} 