import { runSublimeAnalysis } from '../src/server/scanners/sublimeScanner';
import fs from 'fs';
import path from 'path';

async function test() {
  console.log('Testing TypeScript sublimeScanner module...');
  const emlPath = path.join(process.cwd(), 'sublime-rules', 'emls', 'reported_phish.eml');
  const emlContent = fs.readFileSync(emlPath, 'utf8');

  const res = await runSublimeAnalysis(emlContent);
  console.log('TS Sublime Analysis Result:', JSON.stringify(res, null, 2));
}

test();
