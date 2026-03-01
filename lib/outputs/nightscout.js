
var qs = require('querystring');
var url = require('url');
var crypto = require('crypto');

function encode_api_secret(plain) {
  var shasum = crypto.createHash('sha1');
  shasum.update(plain);
  return shasum.digest('hex').toLowerCase( );
}

function nightscoutRestAPI (config, axios) {
  // TODO change this, exposes secret in logs
  console.log("SETTING UP nightscoutRestAPI", config);
  var endpoint = url.parse(config.url);
  var baseURL = url.format({
    protocol: endpoint.protocol
  , host: endpoint.host
  , pathname: endpoint.pathname
  });
  var params = qs.parse(endpoint.query);
  var apiSecret = config.apiSecret;
  var apiHash = encode_api_secret(apiSecret);
  var apiVersion = config.apiVersion || process.env.NIGHTSCOUT_API_VERSION || 'v1';
  var http = axios.create({ baseURL });

  // function gap_for (kind, dt) { }
  // function record_kind (kind, data, dt) { }
  var bookmark = null;

  function record_glucose (data) {
    if (!data.length) {
      console.log("⏭️  Skipping glucose record - no entries to write");
      return Promise.resolve( );
    }
    var headers = { 'API-SECRET': apiHash };
    var endpoint = apiVersion === 'v3' ? '/api/v3/entries' : '/api/v1/entries.json';
    console.log("📤 POSTing", data.length, "glucose entries to", endpoint);
    return http.post(endpoint, data, { headers }).then((resp) => {
      console.log("✅ RECORDED GLUCOSE BATCH:", resp.data.length, "entries written");
      return resp.data;
    }).catch((err) => {
      console.error("❌ RECORDING GLUCOSE ERROR:", err.message || err);
      console.error("   Status:", err.response?.status, "Data:", err.response?.data?.message || err.response?.data);
      throw err;
    });
  }

  function record_treatments (data) {
    if (!data.length) {
      console.log("⏭️  Skipping treatments record - no treatments to write");
      return Promise.resolve( );
    }
    var headers = { 'API-SECRET': apiHash };
    var endpoint = apiVersion === 'v3' ? '/api/v3/treatments' : '/api/v1/treatments.json';
    console.log("📤 POSTing", data.length, "treatments to", endpoint);
    return http.post(endpoint, data, { headers }).then((resp) => {
      console.log("✅ RECORDED TREATMENTS BATCH:", resp.data.length, "treatments written");
      return resp.data;
    }).catch((err) => {
      console.error("❌ RECORDING TREATMENTS ERROR:", err.message || err);
      console.error("   Status:", err.response?.status, "Data:", err.response?.data?.message || err.response?.data);
      throw err;
    });
  }

  function record_devicestatus (data) {
    if (!data.length) {
      console.log("⏭️  Skipping devicestatus record - no data to write");
      return Promise.resolve( );
    }
    var headers = { 'API-SECRET': apiHash };
    var endpoint = apiVersion === 'v3' ? '/api/v3/devicestatus' : '/api/v1/devicestatus.json';
    console.log("📤 POSTing", data.length, "devicestatus entries to", endpoint);
    return http.post(endpoint, data, { headers }).then((resp) => {
      console.log("✅ RECORDED DEVICESTATUS BATCH:", resp.data.length, "devicestatus entries written");
      return resp.data;
    }).catch((err) => {
      console.error("❌ RECORDING DEVICESTATUS ERROR:", err.message || err);
      console.error("   Status:", err.response?.status, "Data:", err.response?.data?.message || err.response?.data);
      throw err;
    });
  }

  function bookmark_glucose (data) {
    var readings = data;
    if (readings && readings.length) {
      var entry = readings[0];
      // Support both dateString and epoch milliseconds (date/mills)
      bookmark.entries = new Date(entry.dateString || entry.date || entry.mills);
    }
    return Promise.resolve(data);
    // return data;
  }

  function record_batch (batch) {
    var { entries, treatments, profiles, devicestatus } = batch;
    entries = entries || [ ];
    treatments = treatments || [ ];
    profiles = profiles || [ ];
    devicestatus = devicestatus || [ ];
    console.log("RECORD BATCH with", entries.length, 'entries,', treatments.length, 'treatments,', devicestatus.length, 'devicestatus');
    /*
    if (!batch.entries.length) {
      return Promise.resolve(bookmark);
    }
    */
    return Promise.all([
        record_glucose(entries).then(bookmark_glucose),
        record_treatments(treatments),
        record_devicestatus(devicestatus)
      ]).then(function update_bookmark (settled) {
        console.log("UPDATE BOOKMARK FROM I/O", bookmark, settled[0], settled.length);
        return bookmark;
    });
    // return Promise.resolve(batch);

  }
  record_batch.gap_for = function ( ) {
    console.log("🔍 FETCHING GAPS INFORMATION");
    if (bookmark) {
      console.log("   Found existing bookmark:", bookmark);
      return Promise.resolve(bookmark);
    }
    bookmark = { };
    var headers = { 'API-SECRET': apiHash };
    var query = { count: 1 };
    var endpoint = apiVersion === 'v3' ? '/api/v3/entries' : '/api/v1/entries.json';
    return http.get(endpoint, { params: query, headers }).then((resp) => {
      if (resp.data && resp.data.length) {
        var entry = resp.data[0];
        // Support both dateString and epoch milliseconds (date/mills)
        bookmark.entries = new Date(entry.dateString || entry.date || entry.mills);
        console.log("✅ UPDATED ENTRIES BOOKMARK to", bookmark.entries);
      } else {
        console.log("⚠️  No entries found to set bookmark");
      }
    }).catch((err) => {
      console.error("❌ FAILED TO DETERMINE GAP:", err.message || err);
      console.error("   Status:", err.response?.status, "Data:", err.response?.data);
    })
    .then(( ) => {
      console.log("📊 FINAL GAP", bookmark);
      return bookmark;
    });

  }
  return record_batch;

}
module.exports = nightscoutRestAPI;

