import { loadNvdCveDatabase } from '../src/server/scanners/cveScanner.js';

async function test() {
  const cveList = await loadNvdCveDatabase();
  console.log('Total records:', cveList.length);
  let undefinedSeverity = 0;
  let undefinedDesc = 0;
  let undefinedId = 0;
  let undefinedSource = 0;

  for (let i = 0; i < cveList.length; i++) {
    const cve = cveList[i];
    if (!cve.id) undefinedId++;
    if (!cve.description) undefinedDesc++;
    if (!cve.sourceIdentifier) undefinedSource++;
    if (!cve.severity) {
      undefinedSeverity++;
      console.log(`Record #${i} (${cve.id}) has undefined severity:`, cve);
    }
  }

  console.log(`Undefined counts -> ID: ${undefinedId}, Desc: ${undefinedDesc}, Source: ${undefinedSource}, Severity: ${undefinedSeverity}`);
}

test();
