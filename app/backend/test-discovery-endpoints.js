// Simple test script for discovery endpoints
const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

async function testEndpoint(endpoint, description) {
  try {
    console.log(`\n🧪 Testing: ${description}`);
    console.log(`📡 Request: GET ${endpoint}`);
    
    const response = await axios.get(`${BASE_URL}${endpoint}`, {
      timeout: 5000,
      headers: {
        'Accept': 'application/json'
      }
    });
    
    console.log(`✅ Success: ${response.status}`);
    console.log(`📊 Response:`, JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    console.log(`❌ Error: ${error.message}`);
    if (error.response) {
      console.log(`📊 Status: ${error.response.status}`);
      console.log(`📊 Response:`, error.response.data);
    }
    return false;
  }
}

async function runTests() {
  console.log('🚀 Starting Discovery API Endpoints Test');
  console.log('==========================================');
  
  const tests = [
    {
      endpoint: '/username/search?query=alice&limit=5',
      description: 'Search endpoint with fuzzy matching'
    },
    {
      endpoint: '/username/trending?timeWindowHours=24&limit=5',
      description: 'Trending creators endpoint'
    },
    {
      endpoint: '/username/recently-active?timeWindowHours=24&limit=5',
      description: 'Recently active users endpoint'
    },
    {
      endpoint: '/username/search?query=al&limit=3',
      description: 'Search with short query (prefix matching)'
    },
    {
      endpoint: '/username/trending?timeWindowHours=1&limit=3',
      description: 'Trending with 1-hour window'
    }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    const success = await testEndpoint(test.endpoint, test.description);
    if (success) {
      passed++;
    } else {
      failed++;
    }
  }
  
  console.log('\n📈 Test Results');
  console.log('================');
  console.log(`✅ Passed: ${passed}`);
  console.log(`❌ Failed: ${failed}`);
  console.log(`📊 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed! The Discovery API is working correctly.');
  } else {
    console.log('\n⚠️  Some tests failed. Please check the server and database configuration.');
  }
}

// Check if server is running first
async function checkServer() {
  try {
    await axios.get(`${BASE_URL}/health`, { timeout: 3000 });
    console.log('✅ Server is running');
    return true;
  } catch (error) {
    console.log('❌ Server is not running or not accessible');
    console.log('💡 Please start the server with: npm run dev');
    return false;
  }
}

async function main() {
  const serverRunning = await checkServer();
  if (serverRunning) {
    await runTests();
  }
}

main().catch(console.error);
