
var qs = require('querystring');
var url = require('url');
var crypto = require('crypto');

var createV3Client = require('../nightscout/api-v3');

function encode_api_secret(plain) {
  var shasum = crypto.createHash('sha1');
  shasum.update(plain);
  return shasum.digest('hex').toLowerCase( );
}

// v1 endpoints and per-collection batching. devicestatus payloads can be
// huge (OpenAPS predictions), so they are chunked to avoid HTTP 413.
var V1_ENDPOINTS = {
  entries: '/api/v1/entries.json'
, treatments: '/api/v1/treatments.json'
, devicestatus: '/api/v1/devicestatus.json'
, profile: '/api/v1/profile.json'
};
var V1_BATCH_SIZE = { devicestatus: 50 };

function nightscoutRestAPI (config, axios) {
  var endpoint = url.parse(config.url);
  var baseURL = url.format({
    protocol: endpoint.protocol
  , host: endpoint.host
  , pathname: endpoint.pathname
  });
  var params = qs.parse(endpoint.query);
  var apiSecret = config.apiSecret;
  var apiHash = apiSecret ? encode_api_secret(apiSecret) : null;
  var apiVersion = config.apiVersion || process.env.NIGHTSCOUT_API_VERSION || 'v1';
  var token = config.token || params.token;
  console.log("SETTING UP nightscoutRestAPI", {
    url: baseURL
  , apiVersion: apiVersion
  , auth: token ? 'token' : (apiSecret ? 'api-secret' : 'none')
  });
  var http = axios.create({ baseURL });
  var v3 = createV3Client({ url: config.url, apiSecret: apiSecret, token: token }, axios);

  var bookmark = null;

  // Fields v3 create computes itself and rejects from clients.
  var V3_SERVER_FIELDS = [ '_id', 'srvModified', 'srvCreated', 'subject', 'modifiedBy' ];

  // v3's canonical time field is the numeric date (+ optional utcOffset).
  // Timezone-bearing strings (created_at/dateString) are re-derived by the
  // server; sending a UTC-rendered string alongside a stored non-zero
  // utcOffset makes dedup updates fail with "Field utcOffset cannot be
  // modified by the client" — so drop them and let date/utcOffset rule.
  function prepare (collection, doc) {
    var out = Object.assign({ }, doc);
    V3_SERVER_FIELDS.forEach(function (field) {
      delete out[field];
    });
    if (!out.app) {
      out.app = 'nightscout-connect';
    }
    if (out.date == null) {
      var when = out.created_at || out.dateString || out.mills || out.timestamp;
      if (when != null) {
        out.date = new Date(when).getTime( );
      }
    }
    if (collection === 'entries') {
      delete out.dateString;
      if (!out.type) {
        out.type = (out.sgv != null) ? 'sgv' : (out.mbg != null ? 'mbg' : 'sgv');
      }
    } else {
      delete out.created_at;
    }
    return out;
  }

  function chunk (data, size) {
    var batches = [ ];
    for (var i = 0; i < data.length; i += size) {
      batches.push(data.slice(i, i + size));
    }
    return batches;
  }

  function post_v1_batch (endpoint, batch, allow_split) {
    var headers = { 'API-SECRET': apiHash };
    return http.post(endpoint, batch, { headers }).then(function (resp) {
      return (resp.data && resp.data.length) || batch.length;
    }).catch(function (err) {
      // Payload too large: split in half and retry each half once.
      if (allow_split && err.response && err.response.status === 413 && batch.length > 1) {
        console.warn("⚠️  HTTP 413 posting", batch.length, "records to", endpoint, "- splitting batch");
        var half = Math.ceil(batch.length / 2);
        return post_v1_batch(endpoint, batch.slice(0, half), false).then(function (a) {
          return post_v1_batch(endpoint, batch.slice(half), false).then(function (b) {
            return a + b;
          });
        });
      }
      throw err;
    });
  }

  function record_collection_v1 (name, data) {
    var endpoint = V1_ENDPOINTS[name];
    var batches = (name === 'profile') ? data.map(function (doc) { return [ doc ]; })
                : chunk(data, V1_BATCH_SIZE[name] || data.length);
    console.log("📤 POSTing", data.length, name, "records to", endpoint, "in", batches.length, "batch(es)");
    return batches.reduce(function (acc, batch) {
      return acc.then(function (tally) {
        return post_v1_batch(endpoint, (name === 'profile') ? batch[0] : batch, true).then(function (written) {
          tally.written += written;
          return tally;
        }).catch(function (err) {
          console.error("❌ ERROR RECORDING", name, "BATCH of", batch.length, ":", err.message || err);
          console.error("   Status:", err.response?.status, "Data:", err.response?.data?.message || err.response?.data);
          tally.failed += batch.length;
          return tally;
        });
      });
    }, Promise.resolve({ written: 0, deduplicated: 0, failed: 0 }));
  }

  function record_collection_v3 (name, data) {
    var api = v3.collection(name);
    var docs = data.map(prepare.bind(null, name));
    console.log("📤 POSTing", docs.length, name, "documents to /api/v3/" + name);
    return docs.reduce(function (acc, doc) {
      return acc.then(function (tally) {
        return api.create(doc).then(function (result) {
          if (result.deduplicated) {
            tally.deduplicated += 1;
            if (result.conflict) {
              console.warn("⚠️  Dedup conflict on", name, "document (kept destination copy):", result.conflictMessage);
            }
          } else {
            tally.written += 1;
          }
          return tally;
        }).catch(function (err) {
          console.error("❌ ERROR RECORDING", name, "DOCUMENT:", err.message || err);
          console.error("   Status:", err.response?.status, "Data:", err.response?.data?.message || err.response?.data);
          tally.failed += 1;
          return tally;
        });
      });
    }, Promise.resolve({ written: 0, deduplicated: 0, failed: 0 }));
  }

  function record_collection (name, data) {
    if (!data || !data.length) {
      return Promise.resolve({ written: 0, deduplicated: 0, failed: 0, data: data || [ ] });
    }
    var writer = (apiVersion === 'v3') ? record_collection_v3 : record_collection_v1;
    return writer(name, data).then(function (tally) {
      console.log("✅ RECORDED", name.toUpperCase( ), "BATCH:", tally.written, "written,", tally.deduplicated, "deduplicated,", tally.failed, "failed");
      if (tally.failed === data.length) {
        // Total failure: reject so the loop machinery backs off and the
        // bookmark does not advance past unwritten data.
        var err = new Error("All " + data.length + " " + name + " records failed to write");
        err.tally = tally;
        throw err;
      }
      tally.data = data;
      return tally;
    });
  }

  // Newest timestamp across docs; batches may arrive ascending (v3 history)
  // or descending (v1 count queries), so never trust doc order.
  function newest_stamp (docs, fields) {
    return docs.reduce(function (newest, doc) {
      var value = null;
      fields.some(function (field) {
        if (doc[field] != null) { value = doc[field]; return true; }
        return false;
      });
      if (value == null) return newest;
      var when = new Date(value);
      return (!newest || when > newest) ? when : newest;
    }, null);
  }

  function bookmark_glucose (result) {
    var readings = result && result.data;
    if (readings && readings.length) {
      var newest = newest_stamp(readings, [ 'dateString', 'date', 'mills' ]);
      if (newest) {
        bookmark = bookmark || { };
        bookmark.entries = newest;
      }
    }
    return Promise.resolve(result);
  }

  function bookmark_profiles (result) {
    var profiles = result && result.data;
    if (profiles && profiles.length) {
      var newest = newest_stamp(profiles, [ 'created_at', 'startDate', 'date', 'mills' ]);
      if (newest) {
        bookmark = bookmark || { };
        bookmark.profiles = newest;
      }
    }
    return Promise.resolve(result);
  }

  function record_batch (batch) {
    var { entries, treatments, profiles, devicestatus } = batch;
    entries = entries || [ ];
    treatments = treatments || [ ];
    profiles = profiles || [ ];
    devicestatus = devicestatus || [ ];
    console.log("RECORD BATCH with", entries.length, 'entries,', treatments.length, 'treatments,', devicestatus.length, 'devicestatus,', profiles.length, 'profiles');
    return Promise.all([
        record_collection('entries', entries).then(bookmark_glucose),
        record_collection('treatments', treatments),
        record_collection('devicestatus', devicestatus),
        record_collection('profile', profiles).then(bookmark_profiles)
      ]).then(function update_bookmark (settled) {
        console.log("UPDATE BOOKMARK FROM I/O", bookmark);
        return bookmark;
    });
  }

  function gap_from_last_modified ( ) {
    return v3.lastModified( ).then(function (result) {
      var collections = (result && result.collections) || { };
      [ 'entries', 'treatments', 'devicestatus' ].forEach(function (name) {
        if (collections[name] != null) {
          bookmark[name] = new Date(collections[name]);
        }
      });
      if (collections.profile != null) {
        bookmark.profiles = new Date(collections.profile);
      }
      if (!bookmark.entries) {
        throw new Error("lastModified response missing entries collection");
      }
      console.log("✅ UPDATED BOOKMARK FROM /api/v3/lastModified", bookmark);
    }).catch(function (err) {
      // Older servers may not implement lastModified; probe latest entry.
      console.warn("⚠️  /api/v3/lastModified unavailable (" + (err.message || err) + "), probing latest entry");
      return v3.collection('entries').search({ limit: 1, 'sort$desc': 'date' }).then(function (result) {
        if (result && result.length) {
          var entry = result[0];
          bookmark.entries = new Date(entry.date || entry.dateString || entry.mills);
          console.log("✅ UPDATED ENTRIES BOOKMARK to", bookmark.entries);
        } else {
          console.log("⚠️  No entries found to set bookmark");
        }
      });
    });
  }

  function gap_from_v1_probe ( ) {
    var headers = { 'API-SECRET': apiHash };
    var query = { count: 1 };
    var entries_probe = http.get('/api/v1/entries.json', { params: query, headers }).then(function (resp) {
      if (resp.data && resp.data.length) {
        var entry = resp.data[0];
        // Support both dateString and epoch milliseconds (date/mills)
        bookmark.entries = new Date(entry.dateString || entry.date || entry.mills);
        console.log("✅ UPDATED ENTRIES BOOKMARK to", bookmark.entries);
      } else {
        console.log("⚠️  No entries found to set bookmark");
      }
    });
    var profile_probe = http.get('/api/v1/profile.json', { params: query, headers }).then(function (resp) {
      if (resp.data && resp.data.length) {
        var newest = newest_stamp(resp.data, [ 'created_at', 'startDate', 'date', 'mills' ]);
        if (newest) bookmark.profiles = newest;
      }
    }).catch(function (err) {
      console.warn("⚠️  Could not probe profile bookmark:", err.message || err);
    });
    return Promise.all([ entries_probe, profile_probe ]);
  }

  record_batch.gap_for = function ( ) {
    console.log("🔍 FETCHING GAPS INFORMATION");
    if (bookmark) {
      console.log("   Found existing bookmark:", bookmark);
      return Promise.resolve(bookmark);
    }
    bookmark = { };
    var probe = (apiVersion === 'v3') ? gap_from_last_modified : gap_from_v1_probe;
    return probe( ).catch(function (err) {
      console.error("❌ FAILED TO DETERMINE GAP:", err.message || err);
      console.error("   Status:", err.response?.status, "Data:", typeof err.response?.data === 'string' ? err.response.data.slice(0, 200) : err.response?.data);
    }).then(function ( ) {
      console.log("📊 FINAL GAP", bookmark);
      if (!bookmark.entries) {
        // Probe failed entirely: hand back the empty gap but do not cache
        // it, so the next frame retries against the destination.
        var current = bookmark;
        bookmark = null;
        return current;
      }
      return bookmark;
    });
  };

  // Expose single-document v3 operations for consumers that need them
  // (READ/UPDATE/PATCH/DELETE/history by identifier).
  record_batch.api = v3;

  return record_batch;

}
module.exports = nightscoutRestAPI;
