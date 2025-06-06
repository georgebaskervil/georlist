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
 * Default fetch timeout in milliseconds - reduced for fail-fast behavior
 */
const FETCH_TIMEOUT = 10000; // 10 seconds instead of 30

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
          source: { type: "string", format: "uri", pattern: "^https://.*" },
        },
        required: ["name", "type", "source"], 
        additionalProperties: false
      }
    },
    transformations: {
      type: "array",
      items: { 
        type: "string",
      },
      description: "Global transformations applied after source-specific ones"
    }
  },
  required: ["name", "description", "sources"],
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
  }[];
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
    const errors = (validate.errors as ErrorObject[])
      .map(error => {
        const instancePath = error.instancePath ? `at ${error.instancePath}` : '';
        return `- ${instancePath} ${error.message}`;
      })
      .join('\n');
      
    throw new Error(`Invalid configuration format:\n${errors}`);
  }
  
  const validConfig = config as unknown as ConfigSchema;

  for (const source of validConfig.sources) {
    if (!source.source.startsWith('https://')) {
       throw new Error(`Invalid source URL in source "${source.name}": "${source.source}". Only HTTPS URLs are allowed.`);
    }
  }

  return true;
}

/**
 * Secure the path to prevent path traversal attacks
 */
function securePath(filePath: string): string {
  const normalizedPath = path.normalize(filePath);
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
  const tempFileName = `${securedPath}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  
  fs.writeFileSync(tempFileName, data, { 
    encoding: 'utf-8',
    mode: 0o644,
    flag: 'wx'
  });
  
  fs.renameSync(tempFileName, securedPath);
}

/**
 * Fetch with timeout and TLS validation
 */
export async function fetchWithTimeout(url: string, timeoutMs = FETCH_TIMEOUT): Promise<Response> {
  if (!url.startsWith('https://')) {
    throw new Error("Only HTTPS URLs are allowed");
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);
  
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}: ${response.statusText} for ${url}`);
    }
    
    const contentType = response.headers.get('content-type');
    if (contentType && !contentType.includes('text/') && !contentType.includes('application/')) {
      throw new Error(`Invalid content type '${contentType}' for ${url}. Expected text content.`);
    }
    
    return response;
  } catch (fetchError) {
    const errorMessage = fetchError instanceof Error ? fetchError.message : String(fetchError);
    throw new Error(`Failed to fetch ${url}: ${errorMessage}`);
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Compile blocklist from sources with fail-fast behavior and debug logging
 */
export async function compileBlocklist(): Promise<string> {
  console.log('[DEBUG] Starting blocklist compilation...');
  const startTime = Date.now();
  
  try {
    // Validate input config exists
    console.log('[DEBUG] Checking for config file...');
    if (!fs.existsSync(CONFIG_PATH)) {
      throw new Error(`Config file not found at ${CONFIG_PATH}`);
    }
    console.log(`[DEBUG] Config file found at: ${CONFIG_PATH}`);

    // Read and parse the configuration file
    console.log('[DEBUG] Reading and parsing configuration file...');
    let config: any;
    try {
      const configContents = fs.readFileSync(CONFIG_PATH, 'utf-8');
      console.log(`[DEBUG] Config file size: ${configContents.length} characters`);
      config = JSON.parse(configContents);
      console.log(`[DEBUG] Config parsed successfully`);
    } catch (parseError: any) {
      console.error('[ERROR] Failed to parse config.json:', parseError);
      throw new Error(`Failed to parse config.json: ${parseError.message}`);
    }

    // Validate configuration
    console.log('[DEBUG] Validating configuration schema...');
    validateConfig(config);
    console.log('[DEBUG] Configuration validation passed');

    const enabledSources = config.sources.filter((source: any) => source.enabled !== false);
    console.log(`[DEBUG] Found ${enabledSources.length} enabled sources out of ${config.sources.length} total`);

    // Fetch all sources with fail-fast behavior
    console.log('[DEBUG] Starting to fetch sources individually...');
    const allRules: string[] = [];
    
    for (let i = 0; i < enabledSources.length; i++) {
      const source = enabledSources[i];
      console.log(`[DEBUG] Fetching source ${i + 1}/${enabledSources.length}: ${source.name}`);
      console.log(`[DEBUG] URL: ${source.source}`);
      
      try {
        const fetchStart = Date.now();
        const response = await fetchWithTimeout(source.source);
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const content = await response.text();
        const fetchTime = Date.now() - fetchStart;
        
        if (!content || content.trim().length === 0) {
          throw new Error(`Empty or invalid response from ${source.source}`);
        }
        
        console.log(`[DEBUG] Successfully fetched ${source.name} in ${fetchTime}ms`);
        console.log(`[DEBUG] Content length: ${content.length} characters`);
        
        // Process lines efficiently to avoid stack overflow
        console.log(`[DEBUG] Processing lines from ${source.name}...`);
        const lines: string[] = [];
        const contentLines = content.split('\n');
        
        for (const line of contentLines) {
          const trimmed = line.trim();
          if (trimmed.length > 0) {
            lines.push(trimmed);
          }
        }
        
        if (lines.length === 0) {
          throw new Error(`No valid lines found in ${source.source}`);
        }
        
        console.log(`[DEBUG] Processed ${lines.length} lines from ${source.name}`);
        
        // Add lines in smaller batches to avoid stack overflow
        const batchSize = 10000;
        for (let j = 0; j < lines.length; j += batchSize) {
          const batch = lines.slice(j, j + batchSize);
          allRules.push(...batch);
        }
        
        console.log(`[DEBUG] Total rules collected so far: ${allRules.length}`);
        
      } catch (error) {
        console.error(`[ERROR] CRITICAL: Failed to fetch ${source.name} from ${source.source}`);
        console.error(`[ERROR] Error details:`, error);
        const errorMessage = error instanceof Error ? error.message : String(error);
        throw new Error(`Compilation failed at source ${i + 1}/${enabledSources.length}: ${source.name}. Error: ${errorMessage}`);
      }
    }

    console.log(`[DEBUG] Finished fetching all sources. Total rules: ${allRules.length}`);

    if (allRules.length === 0) {
      throw new Error("CRITICAL: No rules were collected from any sources. Cannot proceed.");
    }

    // Apply transformations to the concatenated list
    console.log('[DEBUG] Starting transformations...');
    let processedRules = allRules;

    // Remove comments
    console.log('[DEBUG] Removing comments and empty lines...');
    const beforeComments = processedRules.length;
    processedRules = processedRules.filter((rule: string) => {
      const trimmed = rule.trim();
      return trimmed.length > 0 && 
             !trimmed.startsWith('#') && 
             !trimmed.startsWith('!') &&
             !trimmed.startsWith('[');
    });
    console.log(`[DEBUG] Removed ${beforeComments - processedRules.length} comment/header lines`);

    if (processedRules.length === 0) {
      throw new Error("CRITICAL: No valid rules remaining after removing comments.");
    }

    // Deduplicate
    console.log('[DEBUG] Deduplicating rules...');
    const beforeDedup = processedRules.length;
    processedRules = [...new Set(processedRules)];
    console.log(`[DEBUG] Removed ${beforeDedup - processedRules.length} duplicate rules`);

    // Basic validation
    console.log('[DEBUG] Validating rules...');
    const beforeValidation = processedRules.length;
    processedRules = processedRules.filter((rule: string) => {
      const trimmed = rule.trim();
      return trimmed.includes('.') && !trimmed.includes(' ') && trimmed.length > 3;
    });
    console.log(`[DEBUG] Removed ${beforeValidation - processedRules.length} invalid rules`);

    if (processedRules.length === 0) {
      throw new Error("CRITICAL: No valid rules remaining after validation.");
    }

    if (processedRules.length < 100) {
      throw new Error(`CRITICAL: Only ${processedRules.length} rules remaining, which seems too low.`);
    }

    console.log(`[DEBUG] Final rule count: ${processedRules.length}`);

    // Format the output with a header
    console.log('[DEBUG] Creating output with header...');
    const timestamp = new Date();
    const header = [
      `! Title: ${config.name}`,
      `! Last updated: ${timestamp.toISOString()}`,
      `! Description: ${config.description}`,
      config.homepage ? `! Homepage: ${config.homepage}` : '',
      config.license ? `! License: ${config.license}` : '',
      config.version ? `! Version: ${config.version}` : '',
      '! Source count: ' + enabledSources.length,
      '! Rule count: ' + processedRules.length,
      '! Compilation time: ' + (Date.now() - startTime) + 'ms',
      '!'
    ].filter(Boolean).join('\n');

    const outputContent = `${header}\n${processedRules.join('\n')}`;

    if (outputContent.length < 1000) {
      throw new Error(`CRITICAL: Output too small (${outputContent.length} characters).`);
    }

    // Write the output to file
    console.log('[DEBUG] Writing output to file...');
    try {
      secureWriteFile(OUTPUT_PATH, outputContent);
      
      if (!fs.existsSync(OUTPUT_PATH)) {
        throw new Error("Output file was not created successfully");
      }
      
      const writtenSize = fs.statSync(OUTPUT_PATH).size;
      if (writtenSize !== outputContent.length) {
        throw new Error(`File size mismatch: expected ${outputContent.length}, got ${writtenSize}`);
      }
      
    } catch (writeError) {
      console.error('[ERROR] CRITICAL: Failed to write output file:', writeError);
      const errorMessage = writeError instanceof Error ? writeError.message : String(writeError);
      throw new Error(`Failed to write output file: ${errorMessage}`);
    }
    
    const totalTime = Date.now() - startTime;
    console.log(`[DEBUG] Compilation completed successfully in ${totalTime}ms`);
    console.log(`[DEBUG] Output written to: ${OUTPUT_PATH}`);
    console.log(`[DEBUG] Final blocklist size: ${outputContent.length} characters`);

    return outputContent;
  } catch (error) {
    console.error("[ERROR] Compilation failed:", error);
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
