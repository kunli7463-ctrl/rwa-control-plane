#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validateProductionDeployment } from "../src/production-preflight.js";

function parseEnv(source) {
  const env = {};
  for (const [index, raw] of source.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error(`invalid env syntax on line ${index + 1}`);
    if (Object.hasOwn(env, match[1])) throw new Error(`duplicate env key ${match[1]} on line ${index + 1}`);
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    env[match[1]] = value;
  }
  return env;
}

const argument = process.argv[2];
if (!argument || process.argv.length !== 3) {
  console.error("usage: node scripts/validate-production-env.js /absolute/path/to/production.env");
  process.exit(2);
}

const file = resolve(argument);
try {
  const env = parseEnv(await readFile(file, "utf8"));
  const summary = validateProductionDeployment(env, { cwd: process.cwd() });
  console.log("PRODUCTION_PREFLIGHT_OK");
  console.log(JSON.stringify(summary, null, 2));
} catch (error) {
  console.error(`PRODUCTION_PREFLIGHT_FAILED ${error.code ?? "INVALID_ENV"}: ${error.message}`);
  process.exit(1);
}

