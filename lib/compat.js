/**
 * Bridge Plugin Compatibility Layer
 * 
 * Provides backward compatibility with the legacy share2nightscout-bridge plugin
 * by mapping BRIDGE_* environment variables to the new CONNECT_* configuration format.
 */

/**
 * Apply bridge plugin compatibility mappings to a config object
 * @param {Object} config - The configuration object (from CONNECT_* variables)
 * @param {Object} env - The environment variables object
 * @returns {Object} - A new config object with bridge compatibility applied
 */
function applyBridgeCompat(config, env = process.env) {
  // Create a shallow copy to avoid mutating the original
  const result = { ...config };

  // Map BRIDGE_USER_NAME to shareAccountName (only if not already set)
  if (!result.shareAccountName && env.BRIDGE_USER_NAME) {
    result.shareAccountName = env.BRIDGE_USER_NAME;
  }

  // Map BRIDGE_PASSWORD to sharePassword (only if not already set)
  if (!result.sharePassword && env.BRIDGE_PASSWORD) {
    result.sharePassword = env.BRIDGE_PASSWORD;
  }

  // Map BRIDGE_SERVER to shareRegion or shareServer (only if neither is already set)
  if (!result.shareRegion && !result.shareServer && env.BRIDGE_SERVER !== undefined) {
    const server = env.BRIDGE_SERVER;
    
    // Blank/empty string maps to 'us' (old bridge plugin default)
    if (server === '' || server === 'us') {
      result.shareRegion = 'us';
    }
    // EU (case-insensitive) maps to 'ous'
    else if (server.toLowerCase() === 'eu' || server === 'ous') {
      result.shareRegion = 'ous';
    }
    // Custom domains map to shareServer directly
    else if (server.includes('.')) {
      result.shareServer = server;
    }
    // Default: treat as region
    else {
      result.shareRegion = server;
    }
  }

  return result;
}

module.exports = {
  applyBridgeCompat
};
