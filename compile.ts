import fs from "fs";
import { join } from "path";
import { format } from "date-fns";
import compile, { IConfiguration, Transformation } from "@adguard/hostlist-compiler";
import path from "path";
import crypto from "crypto";
import * as Ajv from 'ajv';
import { ErrorObject } from "ajv";
import * as addFormats from 'ajv-formats';
import fetch, { Response } from "node-fetch";
import { AbortController } from "abort-controller";

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
          // Source-specific transformations are optional now (or removed if not needed)
          // transformations: { 
          //   type: "array",
          //   items: { type: "string" }
          // } 
        },
        // 'transformations' is no longer required here
        required: ["name", "type", "source"], 
        additionalProperties: false // Disallow extra properties in sources
      }
    },
    // Add optional root-level transformations
    transformations: {
      type: "array",
      items: { 
        type: "string",
        // You might want to add an enum here if you have a fixed list of valid transformations
        // enum: ["RemoveComments", "Compress", "RemoveModifiers", ...] 
      },
      description: "Global transformations applied after source-specific ones"
    }
  },
  required: ["name", "description", "sources"],
  // Still disallow other extra properties at the root level
  additionalProperties: false 
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
    // Source-specific transformations are optional/removed
    // transformations?: string[]; 
  }[];
  // Root-level transformations remain optional
  transformations?: string[]; 
}

/**
 * Validate configuration against schema using Ajv
 */
function validateConfig(config: any): config is ConfigSchema {
  const ajv = new Ajv.default({ allErrors: true });
  addFormats.default(ajv);
  const validate = ajv.compile(configJsonSchema);
  
  if (!validate(config)) {
    // Format errors for better readability
    const errors = (validate.errors as ErrorObject[])
      .map(error => {
        const instancePath = error.instancePath ? `at ${error.instancePath}` : '';
        return `- ${instancePath} ${error.message}`;
      })
      .join('\n');
      
    throw new Error(`Invalid configuration format:\n${errors}`);
  }
  
  // Explicitly assert the type after validation passes
  // Use a double assertion (any -> unknown -> ConfigSchema)
  const validConfig = config as unknown as ConfigSchema;

  // Additional specific checks not easily covered by schema alone
  for (const source of validConfig.sources) {
    if (!source.source.startsWith('https://')) {
       throw new Error(`Invalid source URL in source "${source.name}": "${source.source}". Only HTTPS URLs are allowed.`);
    }
    // Add any other specific checks here if needed
  }

  return true; // Validation passed
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
  // Create a clean configuration object with only the allowed properties
  const compilerConfig: IConfiguration = {
    name: config.name,
    description: config.description,
    // Map sources without source-specific transformations
    sources: config.sources.map(source => ({
      name: source.name,
      type: source.type,
      source: source.source,
      // Remove source-specific transformations as they are not in ConfigSchema anymore
      // transformations: source.transformations ? source.transformations.map(t => t as unknown as Transformation) : undefined
    }))
  };
  
  // Add optional properties only if they exist in the AdGuard schema
  if (config.homepage) compilerConfig.homepage = config.homepage;
  if (config.license) compilerConfig.license = config.license;
  if (config.version) compilerConfig.version = config.version;
  
  // Add the global transformations if present
  if (Array.isArray(config.transformations)) {
    compilerConfig.transformations = config.transformations.map(t => t as unknown as Transformation);
  }
  
  return compilerConfig;
}

/**
 * Compile blocklist from sources
 */
export async function compileBlocklist(): Promise<string> {
  try {
    console.log("Starting blocklist compilation...");

    // Validate input config exists
    if (!fs.existsSync(CONFIG_PATH)) {
      throw new Error(`Config file not found at ${CONFIG_PATH}`);
    }

    // Read and parse the configuration file
    let config: any;
    try {
      const configContents = fs.readFileSync(CONFIG_PATH, 'utf-8');
      config = JSON.parse(configContents);
    } catch (parseError: any) {
      throw new Error(`Failed to parse config.json: ${parseError.message}`);
    }

    // Validate configuration - this will throw a detailed error if invalid
    validateConfig(config); 

    // Convert to compiler compatible configuration (We know config is valid ConfigSchema now)
    const compilerConfig = convertToCompilerConfig(config as ConfigSchema);

    // Run compilation
    console.log(`Compiling blocklist from ${config.sources.length} sources...`);
    const startTime = Date.now();
    const compiledRules = await compile(compilerConfig);
    const elapsed = Date.now() - startTime;

    // Format the output with a header
    const timestamp = new Date();
    const header = [
      `! Title: ${config.name}`,
      `! Last updated: ${timestamp.toISOString()}`,
      `! Description: ${config.description}`,
      config.homepage ? `! Homepage: ${config.homepage}` : '',
      config.license ? `! License: ${config.license}` : '',
      config.version ? `! Version: ${config.version}` : '',
      '! Source count: ' + config.sources.length,
      '! Rule count: ' + compiledRules.length,
      '! Compilation time: ' + elapsed + 'ms',
      '!'
    ].filter(Boolean).join('\n');

    // Join the header and rules
    const outputContent = `${header}\n${compiledRules.join('\n')}`;

    // Write the output to file
    secureWriteFile(OUTPUT_PATH, outputContent);
    console.log(`Blocklist compiled successfully with ${compiledRules.length} rules`);
    console.log(`Output written to ${OUTPUT_PATH}`);

    return outputContent;
  } catch (error) {
    console.error("Failed to compile blocklist:", error);
    throw error;
  }
}

// Execute if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  compileBlocklist().catch(error => {
    console.error("Compilation failed:", error);
    process.exit(1);
  });
} 