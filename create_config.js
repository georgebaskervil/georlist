const config = {
  name: "GeorList",
  description: "A comprehensive blocklist for AdGuard Home compiled from multiple sources",
  homepage: "https://github.com/georgebaskervil/georlist",
  version: "1.0.0",
  updateInterval: 86400,
  sources: [
    {
      name: "AdGuard and other filter lists",
      type: "adblock",
      source: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",
      transformations: ["Compress", "ValidateAllowIp"]
    },
    {
      name: "AdGuard and other filter lists",
      type: "adblock",
      source: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
      transformations: ["Compress", "ValidateAllowIp"]
    },
    {
      name: "AdGuard and other filter lists",
      type: "adblock",
      source: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
      transformations: ["Compress", "ValidateAllowIp"]
    },
    {
      name: "Malware filter",
      type: "hosts",
      source: "https://malware-filter.gitlab.io/malware-filter/botnet-filter-agh.txt",
      transformations: ["Compress", "ValidateAllowIp"]
    }
  ],
  transformations: [
    "Deduplicate",
    "RemoveEmptyLines",
    "TrimLines",
    "InsertFinalNewLine"
  ]
};

// Convert to JSON string with pretty formatting
const jsonStr = JSON.stringify(config, null, 2);

// Write to file, ensuring no trailing characters
const fs = require('fs');
fs.writeFileSync('config.json', jsonStr, { encoding: 'utf8' });

// Verify the file was written correctly
const content = fs.readFileSync('config.json', 'utf8');
console.log('File length:', content.length);
console.log('Last character code:', content.charCodeAt(content.length - 1));
console.log('Created new config.json successfully!'); 