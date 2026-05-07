# GeorList - AdGuard Hostlist Compiler

GeorList is a GitHub Actions-powered blocklist compiler for AdGuard Home. It compiles custom blocklists from multiple sources and publishes the latest generated list as a GitHub Release asset.

## Features

- Compiles blocklists from multiple sources defined in a configuration file
- Automatically updates blocklists on a GitHub Actions schedule
- Publishes the latest generated blocklist as a downloadable Release asset
- Implements source validation and TLS-only source fetching

## Requirements

- Node.js 18.0 or higher
- npm or yarn package manager

## Installation

### Local Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/georgebaskervil/georlist.git
   cd georlist
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Configure your sources in `config.json` (see Configuration section below)

4. Generate the blocklist locally:

   ```bash
   npm run compile
   ```

## Configuration

The application is configured using a `config.json` file in the root directory. The file should follow this structure:

```json
{
  "name": "GeorList",
  "description": "A comprehensive blocklist for AdGuard Home compiled from multiple sources",
  "homepage": "https://github.com/georgebaskervil/georlist",
  "version": "1.0.0",
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

The scheduled GitHub Action will:

1. Compile the blocklists from the sources specified in `config.json`
2. Create or update the `blocklist` GitHub Release
3. Upload the generated `adguard-blocklist.txt` as a release asset

The update schedule is configured in `.github/workflows/update-blocklist.yml`.

The compiled blocklist will be available at:

```text
https://github.com/georgebaskervil/georlist/releases/download/blocklist/adguard-blocklist.txt
```

You can configure AdGuard Home to use this URL as a blocklist source.

## Development

### Scripts

- `npm start` - Run the one-shot blocklist update
- `npm run compile` - Generate `adguard-blocklist.txt`
- `npm run build` - Build the TypeScript files

## License

[MIT](LICENSE)

## Security

- Only HTTPS sources are allowed in the configuration
- All file paths are validated to prevent path traversal
