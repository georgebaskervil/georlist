import fs from "fs";
import { join } from "path";
import { format } from "date-fns";
import compile, { IConfiguration, Transformation } from "@adguard/hostlist-compiler";
import path from "path";
import crypto from "crypto";
import Ajv from "ajv";

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
 * Schema for config.json using JSON Schema syntax
 */
const configJsonSchema = {
  type: "object",
  properties: {
    name: { type: "string", description: "Name of the blocklist" },
    description: { type: "string", description: "Description of the blocklist" },
    homepage: { type: "string", format: "uri", description: "Homepage URL" },
    license: { type: "string", description: "License identifier (e.g., MIT)" },
    version: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+$", description: "Version string (e.g., 1.0.0)" },
    updateInterval: { type: "integer", minimum: 60, description: "Update interval in seconds (min 60)" },
    sources: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        properties: {
          name: { type: "string" },
          type: { type: "string", enum: ["adblock", "hosts"] },
          source: { type: "string", format: "uri", pattern: "^https://.*" }, // Ensure HTTPS
          transformations: {
            type: "array",
            items: { type: "string" }
          }
        },
        required: ["name", "type", "source", "transformations"],
        additionalProperties: false // Disallow extra properties in sources
      }
    }
  },
  required: ["name", "description", "sources"],
  additionalProperties: false // Disallow extra properties at the root level
};

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
 * Deep inspect objects for potential curly brace issues in strings
 * that might cause formatting errors in chalk
 */
function deepInspectForChalkIssues(obj: unknown, path = ''): { hasIssue: boolean; issues: string[] } {
  const issues: string[] = [];
  
  if (typeof obj === 'string') {
    // Check for unbalanced or suspicious curly braces that might confuse chalk
    let openBraces = 0;
    let lastOpenIndex = -1;
    
    for (let i = 0; i < obj.length; i++) {
      if (obj[i] === '{') {
        openBraces++;
        lastOpenIndex = i;
      } else if (obj[i] === '}') {
        openBraces--;
        // If we have a closing without an opening, that's an issue
        if (openBraces < 0) {
          issues.push(`At ${path}: Potential chalk template issue - found extraneous '}' at position ${i} in "${obj}"`);
          break;
        }
      }
    }
    
    // Check if we have unclosed braces
    if (openBraces > 0) {
      issues.push(`At ${path}: Potential chalk template issue - found unclosed '{' at position ${lastOpenIndex} in "${obj}"`);
    }
    
    // Check for suspicious patterns that might trigger chalk template errors
    if (obj.includes('${') || obj.includes('{} ') || obj.includes('{ }')) {
      issues.push(`At ${path}: Contains potentially problematic pattern for chalk: "${obj}"`);
    }
    
    return { hasIssue: issues.length > 0, issues };
  }
  
  if (obj === null || typeof obj !== 'object') {
    return { hasIssue: false, issues: [] };
  }
  
  // Handle arrays
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const result = deepInspectForChalkIssues(obj[i], `${path}[${i}]`);
      if (result.hasIssue) {
        issues.push(...result.issues);
      }
    }
    return { hasIssue: issues.length > 0, issues };
  }
  
  // Handle objects
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const newPath = path ? `${path}.${key}` : key;
      const result = deepInspectForChalkIssues((obj as any)[key], newPath);
      if (result.hasIssue) {
        issues.push(...result.issues);
      }
    }
  }
  
  return { hasIssue: issues.length > 0, issues };
}

/**
 * Convert our config schema to the AdGuard compiler expected format
 */
function convertToCompilerConfig(config: ConfigSchema): IConfiguration {
  return {
    ...config,
    sources: config.sources.map(source => ({
      ...source,
      // Convert string[] to Transformation[] as required by the compiler
      transformations: source.transformations.map(t => t as unknown as Transformation)
    }))
  };
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
    
    // Extra inspection for potential issues with curly braces in strings
    const inspectionResult = deepInspectForChalkIssues(config);
    if (inspectionResult.hasIssue) {
      console.error("Found potential string formatting issues that may cause chalk errors:");
      for (const issue of inspectionResult.issues) {
        console.error(`- ${issue}`);
      }
      console.error("Please fix these issues in config.json before proceeding.");
      throw new Error("Configuration contains strings that may cause formatting issues in chalk");
    }
    
    // Validate config against JSON Schema using Ajv
    const ajv = new Ajv();
    const validate = ajv.compile(configJsonSchema);
    if (!validate(config)) {
      console.error("Configuration validation failed:");
      console.error(JSON.stringify(validate.errors, null, 2)); // Log detailed Ajv errors
      throw new Error("Configuration file failed validation. Check logs for details.");
    }
    
    // Validate using our type guard to ensure the config matches our ConfigSchema
    if (!validateConfig(config)) {
      throw new Error("Configuration failed type validation");
    }
    
    // Now TypeScript knows 'config' matches the ConfigSchema type
    const validatedConfig: ConfigSchema = config;
    
    // Convert to the format expected by AdGuard hostlist compiler
    const compilerConfig = convertToCompilerConfig(validatedConfig);
    
    // Start timestamp for measuring compilation time
    const startTime = Date.now();
    
    // Set a global timeout for the entire compilation process
    const compilationPromise = new Promise<string[]>(async (resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error("Compilation timed out after 10 minutes"));
      }, 10 * 60 * 1000); // 10 minutes
      
      try {
        // Compile the blocklist - PASSING THE VALIDATED CONFIG
        console.log(`Compiling blocklist from ${validatedConfig.sources.length} sources...`);
        const compiledList = await compile(compilerConfig);
        clearTimeout(timeoutId);
        resolve(compiledList);
      } catch (error) {
        clearTimeout(timeoutId);
        reject(error);
      }
    });
    
    // Wait for compilation to complete
    const compiledList = await compilationPromise;
    
    // Add custom header - USE validatedConfig
    const timestamp = new Date();
    const header = [
      "! Title: Combined AdGuard Home Blocklist",
      `! Last updated: ${format(timestamp, "yyyy-MM-dd HH:mm:ss")}`,
      `! Version: ${validatedConfig.version || "1.0.0"}`, // Use validatedConfig
      `! Total number of sources: ${validatedConfig.sources.length}`, // Use validatedConfig
      `! Total number of rules: ${compiledList.length}`,
      "! Description: A comprehensive blocklist for AdGuard Home compiled from multiple sources",
      `! Homepage: ${validatedConfig.homepage || "https://github.com/yourusername/georlist"}`, // Use validatedConfig
      `! License: ${validatedConfig.license || "MIT"}`, // Use validatedConfig
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
    throw error; // Re-throw error after logging
  }
}

// Run the compilation if this script is executed directly
if (import.meta.main) {
  compileBlocklist().catch((error) => {
    console.error("Compilation failed:", error);
    process.exit(1);
  });
} 