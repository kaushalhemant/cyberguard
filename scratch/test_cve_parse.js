import fs from 'fs';
import path from 'path';

try {
  const jsonPath = path.join(process.cwd(), 'nvdcve-2.0-modified.json');
  console.log('Checking file:', jsonPath, 'Exists:', fs.existsSync(jsonPath));
  if (fs.existsSync(jsonPath)) {
    const fileContent = fs.readFileSync(jsonPath, 'utf8');
    console.log('Read file content length:', fileContent.length);
    const rawJson = JSON.parse(fileContent);
    console.log('Parsed JSON keys:', Object.keys(rawJson));
    console.log('Vulnerabilities length:', rawJson.vulnerabilities?.length || rawJson.CVE_Items?.length || 0);
    if (rawJson.vulnerabilities && rawJson.vulnerabilities.length > 0) {
      console.log('Sample vulnerability structure:', JSON.stringify(rawJson.vulnerabilities[0]).substring(0, 300));
    } else if (rawJson.CVE_Items && rawJson.CVE_Items.length > 0) {
      console.log('Sample CVE_Items structure:', JSON.stringify(rawJson.CVE_Items[0]).substring(0, 300));
    }
  }
} catch (err) {
  console.error('Error in test:', err);
}
