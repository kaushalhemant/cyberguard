import { loadNvdCveDatabase, searchCves } from '../src/server/scanners/cveScanner.js';

async function test() {
  try {
    console.log('Testing loadNvdCveDatabase...');
    const records = await loadNvdCveDatabase();
    console.log('Successfully loaded records:', records.length);
    console.log('Testing searchCves...');
    const searchRes = await searchCves('adobe', 'ALL', 10);
    console.log('Search res matches:', searchRes.totalMatches, 'cves:', searchRes.cves.length);
  } catch (err) {
    console.error('Error during test:', err);
  }
}

test();
