import cron from "node-cron";
import { compileBlocklist } from "./compile.js";
import { join } from "path";
import fs from "fs";
import { format } from "date-fns";
import path from "path";

/**
 * Path to the log file
 */
const LOG_FILE = join(process.cwd(), "cron.log");

// Ensure log directory exists with proper permissions
const LOG_DIR = path.dirname(LOG_FILE);
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { mode: 0o755, recursive: true });
}

/**
 * Maximum log file size (5MB)
 */
const MAX_LOG_SIZE = 5 * 1024 * 1024;

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
 * Log a message to console and file with rotation
 */
function log(message: string): void {
  const timestamp = format(new Date(), "yyyy-MM-dd HH:mm:ss");
  const logMessage = `[${timestamp}] ${message}`;
  
  console.log(logMessage);
  
  try {
    // Secure the log file path
    const secureLogPath = securePath(LOG_FILE);
    
    // Check log file size and rotate if needed
    if (fs.existsSync(secureLogPath)) {
      const stats = fs.statSync(secureLogPath);
      if (stats.size > MAX_LOG_SIZE) {
        // Create a backup of the current log file
        const backupFile = `${secureLogPath}.${format(new Date(), "yyyyMMdd-HHmmss")}.bak`;
        fs.renameSync(secureLogPath, backupFile);
        
        // Start a new log file
        fs.writeFileSync(secureLogPath, `[${timestamp}] Log file rotated\n`, { mode: 0o644 });
      }
    }
    
    // Append to log file with proper permissions
    fs.appendFileSync(secureLogPath, logMessage + "\n", { mode: 0o644 });
  } catch (error) {
    console.error(`Failed to write to log file: ${error}`);
  }
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
    log(`Error reading JSON file ${filePath}: ${error}`);
    return null;
  }
}

/**
 * Maximum consecutive failures before giving up
 */
const MAX_FAILURES = 3;

/**
 * Count of consecutive failures
 */
let consecutiveFailures = 0;

/**
 * Start the cron scheduler
 */
export function startScheduler(cronExpression = "0 0 * * *") {
  log(`Starting scheduler with schedule: ${cronExpression}`);
  
  // Check if the expression is valid
  if (!cron.validate(cronExpression)) {
    throw new Error(`Invalid cron expression: ${cronExpression}`);
  }
  
  // Read update interval from config
  try {
    const configPath = join(process.cwd(), "config.json");
    const config = safeReadJson(configPath);
    
    if (config && config.updateInterval) {
      log(`Config has updateInterval: ${config.updateInterval} seconds`);
    }
  } catch (error) {
    log(`Error reading config: ${error}`);
  }
  
  // First run immediately if no blocklist exists
  const blocklistPath = join(process.cwd(), "adguard-blocklist.txt");
  if (!fs.existsSync(blocklistPath)) {
    log("Blocklist doesn't exist, running initial compilation...");
    
    // Add a small delay to ensure logs are properly initialized
    setTimeout(() => {
      compileBlocklist().then(() => {
        log("Initial compilation completed");
        consecutiveFailures = 0;
      }).catch(error => {
        log(`Initial compilation failed: ${error}`);
        consecutiveFailures++;
      });
    }, 1000);
  }
  
  // Schedule the job with error handling and backoff
  const job = cron.schedule(cronExpression, async () => {
    log("Running scheduled blocklist update...");
    
    // Implement exponential backoff if there are failures
    const backoffMultiplier = Math.min(Math.pow(2, consecutiveFailures), 24); // Max 24 hour backoff
    
    try {
      // If we've failed too many times in a row, log but don't try again
      if (consecutiveFailures >= MAX_FAILURES) {
        log(`Skipping compilation after ${consecutiveFailures} consecutive failures. Manual intervention required.`);
        return;
      }
      
      // If we had a previous failure, wait with exponential backoff
      if (consecutiveFailures > 0) {
        log(`Waiting ${backoffMultiplier} hours before retrying after previous failure...`);
        return; // Skip this attempt, we'll try again later
      }
      
      await compileBlocklist();
      log("Blocklist update completed successfully");
      consecutiveFailures = 0; // Reset on success
    } catch (error) {
      log(`Blocklist update failed: ${error}`);
      consecutiveFailures++;
      
      if (consecutiveFailures >= MAX_FAILURES) {
        log(`Reached maximum consecutive failures (${MAX_FAILURES}). Scheduler will stop attempting compilations.`);
      }
    }
  });
  
  log("Scheduler has been started");
  
  return job;
}

// Execute scheduler if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  // Default to midnight (0 0 * * *), or use custom schedule if provided
  const schedule = process.env.CRON_SCHEDULE || "0 0 * * *";
  
  try {
    const job = startScheduler(schedule);
    
    // Handle termination signals
    process.on("SIGINT", () => {
      log("Received SIGINT, stopping scheduler...");
      job.stop();
      process.exit(0);
    });
    
    process.on("SIGTERM", () => {
      log("Received SIGTERM, stopping scheduler...");
      job.stop();
      process.exit(0);
    });
    
    // Log when the scheduled job runs
    log(`Scheduler started with schedule: ${schedule}`);
  } catch (error) {
    log(`Failed to start scheduler: ${error}`);
    process.exit(1);
  }
} 