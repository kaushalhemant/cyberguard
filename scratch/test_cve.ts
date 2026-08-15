import { searchCves, getLatestCves } from '../src/server/scanners/cveScanner';

async function test() {
  console.log('Testing NIST NVD CVE Search...');
  const searchResult = await searchCves('adobe', 'ALL', 3);
  console.log(`Matched ${searchResult.totalMatches} CVE records for query 'adobe'. First 3 results:`);
  console.log(JSON.stringify(searchResult.cves, null, 2));

  const latest = await getLatestCves(2);
  console.log('\nLatest CVEs count:', latest.length);
}

test();
