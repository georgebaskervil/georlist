# GeorList - AdGuard Hostlist Compiler

GeorList is a Node.js application that compiles custom blocklists for AdGuard Home from multiple sources.

## Features

- Compiles blocklists from multiple sources defined in a configuration file
- Automatically updates blocklists on a configurable schedule
- Serves blocklists via HTTP for use with AdGuard Home
- Implements security best practices including rate limiting and TLS validation
- Supports Docker deployment

## Requirements

- Node.js 18.0 or higher
- npm or yarn package manager

## Installation

### Local Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/georlist.git
   cd georlist
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Configure your sources in `config.json` (see Configuration section below)

4. Start the application:
   ```
   npm start
   ```

### Docker Installation

1. Build the Docker image:
   ```
   docker build -t georlist .
   ```

2. Run the container:
   ```
   docker run -p 3000:3000 -v $(pwd)/config.json:/app/config.json georlist
   ```

## Configuration

The application is configured using a `config.json` file in the root directory. The file should follow this structure:

```json
{
  "name": "GeorList",
  "description": "A comprehensive blocklist for AdGuard Home compiled from multiple sources",
  "homepage": "https://github.com/yourusername/georlist",
  "version": "1.0.0",
  "updateInterval": 86400,
  "sources": [
    {
      "name": "Example Filter List",
      "type": "adblock",
      "source": "https://example.com/filterlist.txt",
      "transformations": [
        "Compress",
        "ValidateAllowIp"
      ]
    }
  ],
  "transformations": [
    "Deduplicate",
    "RemoveEmptyLines",
    "TrimLines",
    "InsertFinalNewLine"
  ]
}
```

## Usage

Once running, the application will:

1. Compile the blocklists from the sources specified in `config.json`
2. Start a web server to serve the compiled blocklist
3. Set up a cron job to automatically update the blocklist based on the schedule

The compiled blocklist will be available at:
```
http://localhost:3000/blocklist.txt
```

You can configure AdGuard Home to use this URL as a blocklist source.

## Development

### Scripts

- `npm start` - Start the application
- `npm run dev` - Start the application in development mode with auto-reload
- `npm run server` - Start only the web server
- `npm run compile` - Run only the blocklist compilation
- `npm run cron` - Run only the scheduler
- `npm run build` - Build the TypeScript files

## License

[MIT](LICENSE)

## Security

- Only HTTPS sources are allowed in the configuration
- All file paths are validated to prevent path traversal
- Rate limiting is implemented to prevent abuse
- Security headers are set on all responses 