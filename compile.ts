import fs from "fs";
import { join } from "path";
import { format } from "date-fns";
import compile from "@adguard/hostlist-compiler";
import path from "path";
import crypto from "crypto";

/**
 * Path to the configuration file
 */
const CONFIG_PATH = join(process.cwd(), "config.json");

/**
 * Path to the output blocklist file
 */
const OUTPUT_PATH = join(process.cwd(), "adguard-blocklist.txt");

/**
 * Default fetch timeout in milliseconds
 */
const FETCH_TIMEOUT = 30000;

/**
 * Schema for validating config.json
 */
interface ConfigSchema {
  name: string;
  description: string;
  homepage?: string;
  license?: string;
  version?: string;
  updateInterval?: number;
  sources: {
    name: string;
    type: "adblock" | "hosts";
    source: string;
    transformations: string[];
  }[];
}

/**
 * Validate configuration against schema
 */
function validateConfig(config: any): config is ConfigSchema {
  // Check basic structure
  if (!config || typeof config !== 'object') return false;
  
  // Check required fields
  if (typeof config.name !== 'string') return false;
  if (typeof config.description !== 'string') return false;
  
  // Check sources array
  if (!Array.isArray(config.sources)) return false;
  
  // Validate each source
  for (const source of config.sources) {
    if (typeof source !== 'object') return false;
    if (typeof source.name !== 'string') return false;
    if (source.type !== 'adblock' && source.type !== 'hosts') return false;
    if (typeof source.source !== 'string') return false;
    if (!source.source.startsWith('https://')) return false; // Require HTTPS
    if (!Array.isArray(source.transformations)) return false;
  }
  
  // Optional fields
  if (config.homepage !== undefined && typeof config.homepage !== 'string') return false;
  if (config.license !== undefined && typeof config.license !== 'string') return false;
  if (config.version !== undefined && typeof config.version !== 'string') return false;
  if (config.updateInterval !== undefined && typeof config.updateInterval !== 'number') return false;
  
  return true;
}

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
 * Safely write to a file with proper permissions
 */
function secureWriteFile(filePath: string, data: string): void {
  const securedPath = securePath(filePath);
  
  // Create a temporary file first
  const tempFileName = `${securedPath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  
  // Write to the temporary file
  fs.writeFileSync(tempFileName, data, { 
    encoding: 'utf-8',
    mode: 0o644, // rw-r--r--
    flag: 'wx'   // Fail if file exists
  });
  
  // Rename the temporary file to the target (atomic operation)
  fs.renameSync(tempFileName, securedPath);
}

/**
 * Fetch with timeout and TLS validation
 */
export async function fetchWithTimeout(url: string, timeoutMs = FETCH_TIMEOUT): Promise<Response> {
  // Validate URL (only allow https:// URLs)
  if (!url.startsWith('https://')) {
    throw new Error("Only HTTPS URLs are allowed");
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
      }
    });
    
    // Validate the response
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
    }
    
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Compile the blocklist using AdGuard's hostlist compiler
 */
export async function compileBlocklist(): Promise<string> {
  try {
    console.log("Starting blocklist compilation with AdGuard hostlist compiler...");
    
    // Read configuration
    if (!fs.existsSync(CONFIG_PATH)) {
      throw new Error(`Configuration file not found: ${CONFIG_PATH}`);
    }
    
    // Securely read and parse the config file
    const configContent = fs.readFileSync(securePath(CONFIG_PATH), "utf-8");
    let config: unknown;
    
    try {
      config = JSON.parse(configContent);
    } catch (error) {
      throw new Error(`Invalid JSON in configuration file: ${error}`);
    }
    
    // Validate config against schema
    if (!validateConfig(config)) {
      throw new Error("Configuration file failed validation");
    }
    
    // Start timestamp for measuring compilation time
    const startTime = Date.now();
    
    // Set a global timeout for the entire compilation process
    const compilationPromise = new Promise<string[]>(async (resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error("Compilation timed out after 10 minutes"));
      }, 10 * 60 * 1000); // 10 minutes
      
      try {
        // Compile the blocklist
        console.log(`Compiling blocklist from ${config.sources.length} sources...`);
        const compiledList = await compile(config);
        clearTimeout(timeoutId);
        resolve(compiledList);
      } catch (error) {
        clearTimeout(timeoutId);
        reject(error);
      }
    });
    
    // Wait for compilation to complete
    const compiledList = await compilationPromise;
    
    // Add custom header
    const timestamp = new Date();
    const header = [
      "! Title: Combined AdGuard Home Blocklist",
      `! Last updated: ${format(timestamp, "yyyy-MM-dd HH:mm:ss")}`,
      `! Version: ${config.version || "1.0.0"}`,
      `! Total number of sources: ${config.sources.length}`,
      `! Total number of rules: ${compiledList.length}`,
      "! Description: A comprehensive blocklist for AdGuard Home compiled from multiple sources",
      `! Homepage: ${config.homepage || "https://github.com/yourusername/georlist"}`,
      `! License: ${config.license || "MIT"}`,
      "!"
    ].join("\n");
    
    // Combine header and compiled list
    const finalList = header + "\n" + compiledList.join("\n");
    
    // Write to file
    secureWriteFile(OUTPUT_PATH, finalList);
    
    // Calculate compilation time
    const compilationTime = (Date.now() - startTime) / 1000;
    
    console.log(`Blocklist compilation complete in ${compilationTime.toFixed(2)} seconds.`);
    console.log(`Output saved to: ${OUTPUT_PATH}`);
    console.log(`Total rules: ${compiledList.length}`);
    
    return OUTPUT_PATH;
  } catch (error) {
    console.error("Error compiling blocklist:", error);
    throw error;
  }
}

// Run the compilation if this script is executed directly
if (import.meta.main) {
  compileBlocklist().catch((error) => {
    console.error("Compilation failed:", error);
    process.exit(1);
  });
} 