import http from 'http';

function testEndpoint(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, body });
      });
    }).on('error', reject);
  });
}

async function run() {
  try {
    console.log('Testing GET http://localhost:3000/api/cve/search?query=adobe ...');
    const res = await testEndpoint('http://localhost:3000/api/cve/search?query=adobe');
    console.log('Response status:', res.statusCode);
    console.log('Response body preview:', res.body.substring(0, 300));
  } catch (e) {
    console.error('Request error:', e.message);
  }
}

run();
