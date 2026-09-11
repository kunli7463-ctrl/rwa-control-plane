import { readFile, writeFile } from 'node:fs/promises';
import { buildMarketDraft } from '../src/market-draft.js';

// No database access, credentials, networking or automatic activation.
const [inputPath, templatePath, outputPath, ...extra] = process.argv.slice(2);
if (!inputPath || !templatePath || !outputPath || extra.length) {
  throw new Error('Usage: node scripts/build-market-draft.js input.json template.json output.json');
}
const input = JSON.parse(await readFile(inputPath, 'utf8'));
const template = JSON.parse(await readFile(templatePath, 'utf8'));
const draft = buildMarketDraft(input, template);
await writeFile(outputPath, JSON.stringify(draft, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
console.log('MARKET_DRAFT_CREATED_NOT_APPROVED');
