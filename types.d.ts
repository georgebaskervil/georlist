declare module "@adguard/hostlist-compiler" {
  export interface Source {
    name?: string;
    source: string;
    type?: "adblock" | "hosts";
    transformations?: Transformation[];
    exclusions?: string[];
    exclusions_sources?: string[];
    inclusions?: string[];
    inclusions_sources?: string[];
  }
  
  export type Transformation = 
    | "RemoveComments"
    | "Compress"
    | "RemoveModifiers"
    | "Validate"
    | "ValidateAllowIp"
    | "Deduplicate"
    | "InvertAllow"
    | "RemoveEmptyLines"
    | "TrimLines"
    | "InsertFinalNewLine"
    | "ConvertToAscii";
  
  export interface IConfiguration {
    name: string;
    description?: string;
    homepage?: string;
    license?: string;
    version?: string;
    updateInterval?: number;
    sources: Source[];
    transformations?: Transformation[];
    exclusions?: string[];
    exclusions_sources?: string[];
    inclusions?: string[];
    inclusions_sources?: string[];
  }
  
  /**
   * Compile function for the hostlist compiler
   * @param config Configuration object or array of URLs
   * @returns Array of compiled rules
   */
  function compile(config: IConfiguration | string[]): Promise<string[]>;
  
  export default compile;
} 