# AdGuard Home Blocklist Compiler

A Bun.js application that compiles a comprehensive blocklist for AdGuard Home from multiple sources, serves it over the web, and updates it daily.

## Features

- Uses AdGuard's official hostlist-compiler for optimal list generation
- Compiles blocklists from multiple sources into a single AdGuard Home compatible list
- Preserves IP addresses with ValidateAllowIp transformation
- Deduplicates and optimizes the blocklist
- Serves the blocklist over HTTP with proper caching headers
- Automatically updates the list daily via cron scheduling
- Provides statistics and health check endpoints
- Simple and efficient
- Docker support for easy deployment

## Requirements

- [Bun.js](https://bun.sh) (v1.0.0 or higher)
- Or Docker for containerized deployment

## Installation

### Standard Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/georlist.git
   cd georlist
   ```

2. Install dependencies:
   ```bash
   bun install
   ```

### Docker Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/georlist.git
   cd georlist
   ```

2. Build and start with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Usage

### Standard Usage

#### Start the Complete Application (Server + Scheduler)

```bash
bun run start
```

This will:
1. Compile the blocklist if it doesn't exist or is outdated
2. Start a web server to serve the blocklist
3. Setup a scheduler to update the blocklist daily

#### Compile Blocklist Only

```bash
bun run compile
```

#### Start Web Server Only

```bash
bun run server
```

#### Start Scheduler Only

```bash
bun run cron
```

### Docker Usage

#### Start the Container

```bash
docker-compose up -d
```

#### View Logs

```bash
docker-compose logs -f
```

#### Rebuild and Restart

```bash
docker-compose up -d --build
```

## Integration with AdGuard Home

In your AdGuard Home settings:

1. Go to "Filters"
2. Click "Add blocklist"
3. Enter the URL to your server: `http://your-server-ip:3000/blocklist.txt`
4. Click "Save"

## Web Server Endpoints

- `GET /` or `/blocklist.txt` - Serves the compiled blocklist file
- `GET /health` - Health check endpoint
- `GET /stats` - Provides statistics about the blocklist
- `POST /refresh` - Triggers a manual refresh of the blocklist

## Configuration

### Environment Variables

- `PORT` - Port for the web server (default: 3000)
- `HOST` - Host for the web server (default: localhost)
- `CRON_SCHEDULE` - Cron schedule for updates (default: "0 0 * * *" - midnight)

### Config File (config.json)

The `config.json` file contains the configuration for the AdGuard hostlist compiler:

- `sources`: Array of filter list sources with transformations
- `transformations`: Global transformations applied to the final list
- `updateInterval`: Update interval in seconds (default: 86400 - 1 day)

## How It Works

The application:

1. Uses AdGuard's hostlist-compiler to process filter lists
2. Applies specific transformations to each source
3. Preserves IP addresses while optimizing the list
4. Serves the compiled list via HTTP with proper caching headers
5. Updates the list on a daily schedule
6. Provides statistics and health checks

## Transformations Used

- `Compress` - Converts hosts-style rules to AdGuard syntax
- `ValidateAllowIp` - Validates rules while preserving IP addresses
- `Deduplicate` - Removes duplicate rules
- `RemoveEmptyLines` - Cleans up empty lines
- `TrimLines` - Removes whitespace from lines
- `InsertFinalNewLine` - Ensures the file ends with a newline

## License

MIT 