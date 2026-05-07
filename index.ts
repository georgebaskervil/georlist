import { compileBlocklist } from "./compile.js";

async function main() {
    console.log("Starting GeorList blocklist update");

    try {
        await compileBlocklist();
        console.log("GeorList blocklist update completed successfully");
    } catch (error) {
        console.error("GeorList blocklist update failed:", error);
        process.exit(1);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    await main();
}

export { main };