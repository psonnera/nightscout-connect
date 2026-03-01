// Test suite for Bridge Plugin Compatibility Layer
const { applyBridgeCompat } = require('./lib/compat');

console.log('Testing Bridge Compatibility Layer\n');

let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    console.log(`Test ${testsPassed + testsFailed + 1}: ${name}`);
    fn();
    console.log('✓ Passed\n');
    testsPassed++;
  } catch (error) {
    console.log(`✗ Failed: ${error.message}\n`);
    testsFailed++;
  }
}

function assertEquals(actual, expected, message) {
  const actualStr = JSON.stringify(actual, null, 2);
  const expectedStr = JSON.stringify(expected, null, 2);
  console.log(`Result: ${actualStr}`);
  
  if (actualStr !== expectedStr) {
    throw new Error(`${message}\nExpected: ${expectedStr}\nActual: ${actualStr}`);
  }
}

// Test 1: Empty config with BRIDGE_ env vars
test('Empty config with BRIDGE_ env vars', () => {
  const env = {
    BRIDGE_USER_NAME: 'testuser',
    BRIDGE_PASSWORD: 'testpass',
    BRIDGE_SERVER: 'us'
  };
  
  const config = {};
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'testuser',
    sharePassword: 'testpass',
    shareRegion: 'us'
  }, 'Should map BRIDGE_ vars to CONNECT_ vars');
});

// Test 2: New CONNECT_ vars should take precedence over BRIDGE_ vars
test('New CONNECT_ vars should take precedence over BRIDGE_ vars', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: 'ous'
  };
  
  const config = {
    shareAccountName: 'connect_user',
    sharePassword: 'connect_pass',
    shareRegion: 'us'
  };
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'connect_user',
    sharePassword: 'connect_pass',
    shareRegion: 'us'
  }, 'CONNECT_ vars should completely override BRIDGE_ vars');
  console.log('✓ Passed - BRIDGE vars completely ignored when CONNECT vars present\n');
});

// Test 2b: Only unset CONNECT_ vars should fallback to BRIDGE_ vars
test('Only unset CONNECT_ vars should fallback to BRIDGE_ vars', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: 'ous'
  };
  
  const config = {
    shareAccountName: 'connect_user'
  };
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'connect_user',
    sharePassword: 'bridge_pass',
    shareRegion: 'ous'
  }, 'Should selectively fallback to BRIDGE_ vars for unset CONNECT_ vars');
  console.log('✓ Passed - Selective fallback works correctly\n');
});

// Test 3: BRIDGE_SERVER="" (blank) should map to shareRegion=us
test('BRIDGE_SERVER="" (blank) should map to shareRegion=us', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: ''
  };
  
  const config = {};
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'bridge_user',
    sharePassword: 'bridge_pass',
    shareRegion: 'us'
  }, 'Blank BRIDGE_SERVER should map to us region (old default)');
});

// Test 4: BRIDGE_SERVER=EU (uppercase) should map to shareRegion=ous
test('BRIDGE_SERVER=EU (uppercase) should map to shareRegion=ous', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: 'EU'
  };
  
  const config = {};
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'bridge_user',
    sharePassword: 'bridge_pass',
    shareRegion: 'ous'
  }, 'EU should map to ous region');
});

// Test 5: BRIDGE_SERVER=eu (lowercase) should map to shareRegion=ous
test('BRIDGE_SERVER=eu (lowercase) should map to shareRegion=ous', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: 'eu'
  };
  
  const config = {};
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'bridge_user',
    sharePassword: 'bridge_pass',
    shareRegion: 'ous'
  }, 'eu (lowercase) should map to ous region');
});

// Test 6: Custom server domain
test('Custom server domain', () => {
  const env = {
    BRIDGE_USER_NAME: 'bridge_user',
    BRIDGE_PASSWORD: 'bridge_pass',
    BRIDGE_SERVER: 'custom.dexcom.com'
  };
  
  const config = {};
  const result = applyBridgeCompat(config, env);
  
  assertEquals(result, {
    shareAccountName: 'bridge_user',
    sharePassword: 'bridge_pass',
    shareServer: 'custom.dexcom.com'
  }, 'Custom domain should map to shareServer');
});

// Summary
console.log('\nAll tests passed! ✓');
if (testsFailed > 0) {
  console.log(`\n${testsFailed} test(s) failed.`);
  process.exit(1);
}
