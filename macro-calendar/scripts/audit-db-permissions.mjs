#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const migrationsDir = path.join(repoRoot, "supabase", "migrations");

if (!fs.existsSync(migrationsDir)) {
  console.error("❌ Missing migrations directory:", migrationsDir);
  process.exit(1);
}

const sqlFiles = fs
  .readdirSync(migrationsDir)
  .filter((f) => f.endsWith(".sql") && !f.includes("_test_"))
  .sort();

const corpus = sqlFiles
  .map((file) => fs.readFileSync(path.join(migrationsDir, file), "utf8"))
  .join("\n\n")
  .toLowerCase();

const checks = [
  {
    name: "revoke audit_log from anon/authenticated",
    ok:
      /revoke\s+all\s+on\s+table\s+public\.audit_log\s+from\s+anon\s*,\s*authenticated\s*;/i.test(
        corpus
      ) ||
      /revoke\s+all\s+on\s+table\s+audit_log\s+from\s+anon\s*,\s*authenticated\s*;/i.test(corpus),
  },
  {
    name: "revoke request_logs from anon/authenticated",
    ok:
      /revoke\s+all\s+on\s+table\s+public\.request_logs\s+from\s+anon\s*,\s*authenticated\s*;/i.test(
        corpus
      ) ||
      /revoke\s+all\s+on\s+table\s+request_logs\s+from\s+anon\s*,\s*authenticated\s*;/i.test(corpus),
  },
  {
    name: "grant audit_log to service_role",
    ok:
      /grant\s+select\s*,\s*insert\s+on\s+table\s+public\.audit_log\s+to\s+service_role\s*;/i.test(
        corpus
      ) ||
      /grant\s+select\s*,\s*insert\s+on\s+table\s+audit_log\s+to\s+service_role\s*;/i.test(corpus),
  },
  {
    name: "grant request_logs to service_role",
    ok:
      /grant\s+select\s*,\s*insert\s+on\s+table\s+public\.request_logs\s+to\s+service_role\s*;/i.test(
        corpus
      ) ||
      /grant\s+select\s*,\s*insert\s+on\s+table\s+request_logs\s+to\s+service_role\s*;/i.test(corpus),
  },
];

const failed = checks.filter((c) => !c.ok);

if (failed.length) {
  console.error("❌ DB permission audit failed:");
  for (const item of failed) {
    console.error(`  - Missing: ${item.name}`);
  }
  process.exit(1);
}

console.log("✅ DB permission audit passed");
for (const item of checks) {
  console.log(`  - ${item.name}`);
}
