
// var qs = require('querystring');
var qs = require('qs');
var url = require('url');
var crypto = require('crypto');

var software = require('../../package.json');
var user_agent_string = [software.name, `${software.name}@${software.version}`, 'Nightscout API', software.homepage].join(', ');

function encode_api_secret(plain) {
  var shasum = crypto.createHash('sha1');
  shasum.update(plain);
  return shasum.digest('hex').toLowerCase( );
}

var SERVER_FIELDS = [ '_id', 'identifier', 'srvModified', 'srvCreated', 'subject', 'modifiedBy' ];
var HISTORY_LIMIT = 1000;
var MAX_HISTORY_PAGES = 5;

function nightscoutSource (opts, axios) {

  var endpoint = url.parse(opts.url);
  var baseURL = url.format({
    protocol: endpoint.protocol || 'https'
  , host: endpoint.host
  , pathname: endpoint.pathname
  });
  var params = qs.parse(endpoint.query);
  var apiSecret = opts.apiSecret;
  var apiHash = encode_api_secret(apiSecret);
  // 'auto' probes /api/v3/version once and falls back to v1.
  var configuredApiVersion = (opts.apiVersion || process.env.CONNECT_SOURCE_API_VERSION || process.env.NIGHTSCOUT_API_VERSION || 'auto').toLowerCase( );

  console.log("NIGHTSCOUT BASE URL", baseURL, "API VERSION", configuredApiVersion);
  var default_headers = {
    'User-Agent': user_agent_string
  };
  var http = axios.create({
    baseURL,
    headers: default_headers,
    paramsSerializer: params => qs.stringify(params, { arrayFormat: 'brackets' })
  });

  var detectedApiVersion = null;
  var detectionPromise = null;

  function detectApiVersion ( ) {
    if (configuredApiVersion === 'v1' || configuredApiVersion === 'v3') {
      detectedApiVersion = configuredApiVersion;
      return Promise.resolve(detectedApiVersion);
    }
    if (detectionPromise) {
      return detectionPromise;
    }
    console.log("NIGHTSCOUT: Detecting API version...");
    detectionPromise = http.get('/api/v3/version')
      .then((resp) => {
        if (resp.data && resp.data.result && resp.data.result.apiVersion) {
          detectedApiVersion = 'v3';
          console.log("NIGHTSCOUT: Detected API V3", resp.data.result.apiVersion);
          return 'v3';
        }
        detectedApiVersion = 'v1';
        console.log("NIGHTSCOUT: Using API V1 (V3 response invalid)");
        return 'v1';
      })
      .catch((err) => {
        detectedApiVersion = 'v1';
        console.log("NIGHTSCOUT: Using API V1 (V3 not available)", err.message);
        return 'v1';
      });
    return detectionPromise;
  }

  // v3 wraps payloads in { status, result }.
  function unwrapV3 (resp) {
    if (resp.data && typeof resp.data === 'object' && resp.data.result !== undefined) {
      return resp.data.result;
    }
    return resp.data;
  }

  function auth_headers (session) {
    var headers = { };
    if (session && session.bearer) {
      headers['Authorization'] = ['Bearer', session.bearer].join(' ');
    }
    return headers;
  }

  function align_to_glucose_shared (last_known) {
    if (!last_known || !last_known.entries) {
      return;
    }
    var last_glucose_at = last_known.entries;
    var missing = ((new Date( )).getTime( ) - last_glucose_at.getTime( )) / (1000 * 60 * 5)
    if (missing > 1 && missing < 3) {
      console.log("READJUSTING SHOULD MAKE A DIFFERENCE MISSING", missing);
    }
    var next_due = last_glucose_at.getTime( ) + (Math.ceil(missing) * 1000 * 60 * 5);
    var buffer_lag = 18000; // 18 second buffer
    var jitter = Math.floor(Math.random( ) * 1000 * 18); // 18 second random
    var align_to = next_due + buffer_lag + jitter;
    return align_to;
  }

  function strip_server_fields (doc) {
    var out = Object.assign({ }, doc);
    SERVER_FIELDS.forEach(function (field) {
      delete out[field];
    });
    return out;
  }

  // Shared subject/token exchange: authorization always lives under
  // /api/v1/verifyauth and /api/v2/authorization/* even for v3 data reads.
  function token_from_subjects ( ) {
    var authURL = '/api/v2/authorization/subjects';
    var headers = { 'API-SECRET': apiHash };
    return http.get(authURL, { headers }).then((resp) => {
      var body = resp.data;
      var match = body.filter((item) => item.name == 'nightscout-connect-reader').pop( );
      if (match) {
        return match.accessToken;
      }
      // NB: the field is 'roles' (plural); 'role' is silently ignored and
      // yields a permissionless subject.
      var subject = {
        name: 'nightscout-connect-reader',
        roles: [ 'readable' ],
        notes: 'Used by nightscout-connect to read Nightscout as a source of data.'
      };
      return http.post(authURL, subject, { headers }).then((resp) => {
        return http.get(authURL, { headers }).then((resp) => {
          var body = resp.data;
          var match = body.filter((item) => item.name == 'nightscout-connect-reader').pop( );
          if (match) {
            params.token = match.accessToken;
            return params.token;
          }
          return Promise.reject(body);
        }).catch(err => {
          console.error("❌ authFromCredentials: Failed to retrieve subject token", err.message || err);
          throw err;
        });
      }).catch(err => {
        console.error("❌ authFromCredentials: Failed to create subject", err.message || err);
        throw err;
      });
    }).catch(err => {
      console.error("❌ authFromCredentials: Failed to get authorization subjects", err.message || err);
      throw err;
    });
  }

  function jwt_session_from_token (accessToken) {
    var tokenUrl = '/api/v2/authorization/request/' + accessToken;
    return http.get(tokenUrl).then((resp) => {
      var body = resp.data;
      var session = {
        bearer: body.token
      , ttl: (body.exp - body.iat) * 1000
      , info: body
      }
      return session;
    });
  }

  // ---------------------------------------------------------------- V1 ----
  var implV1 = {
    authFromCredentials (creds, settings) {
      var checkURL = '/api/v1/verifyauth';
      // prefer using a token for traceability reasons
      if (params.token) return Promise.resolve(params.token);
      // check if it's already readable
      return http.get(checkURL).then((resp) => {
        var checked = resp.data;
        if (checked.status == 200 && checked.message.canRead) {
          return Promise.resolve({ readable: checked });
        }
        // otherwise exchange API Secret for a token for traceability reasons.
        return token_from_subjects( );
      }).catch(err => {
        console.error("❌ authFromCredentials FAILED:", err.message || err);
        throw err;
      });
    },
    sessionFromAuth (accessToken, settings) {
      if (accessToken && accessToken.readable) {
        return Promise.resolve({ readable: accessToken.readable });
      }
      return jwt_session_from_token(accessToken);
    },
    align_to_glucose: align_to_glucose_shared,
    dataFromSesssion (session, last_known) {
      var two_days_ago = new Date( ).getTime( ) - (2 * 24 * 60 * 60 * 1000);
      var last_mills = Math.max(two_days_ago, (last_known && last_known.entries) ? last_known.entries.getTime( ) : two_days_ago);
      var count = Math.ceil(((new Date( )).getTime( ) - last_mills) / (1000 * 60 * 5));
      // Fetch a larger batch without find filter to work around API compatibility issues
      var query = { count: Math.min(count + 10, 100) };
      var headers = auth_headers(session);
      console.log("FETCHING GAPS FOR", last_known, "last_mills:", last_mills, "query:", query);

      // Fetch entries, devicestatus, treatments, and profiles in parallel
      return Promise.all([
        http.get('/api/v1/entries.json', { params: query, headers }),
        http.get('/api/v1/devicestatus.json', { params: query, headers }),
        http.get('/api/v1/treatments.json', { params: query, headers }),
        http.get('/api/v1/profile.json', { headers }).catch((err) => {
          console.warn("⚠️  Could not fetch profiles from source:", err.message || err);
          return { data: [ ] };
        })
      ]).then((responses) => {
        var [entriesResp, devicestatusResp, treatmentsResp, profileResp] = responses;

        var filtered = (entriesResp.data || []).filter(function (entry) {
          var entryMills = entry.mills || entry.date || new Date(entry.dateString).getTime( );
          return entryMills >= last_mills;
        });
        console.log("FETCHED", filtered.length, "new entries from", (entriesResp.data || []).length, "total");

        var devicestatus = (devicestatusResp.data || []).filter(function (status) {
          var statusMills = new Date(status.created_at).getTime( );
          return statusMills >= last_mills;
        });
        console.log("FETCHED", devicestatus.length, "new devicestatus entries from", (devicestatusResp.data || []).length, "total");

        var treatments = (treatmentsResp.data || []).filter(function (treatment) {
          var treatmentMills = new Date(treatment.created_at || treatment.timestamp || treatment.mills).getTime( );
          return treatmentMills >= last_mills;
        });
        console.log("FETCHED", treatments.length, "new treatments from", (treatmentsResp.data || []).length, "total");

        var all_profiles = profileResp.data || [ ];
        var profiles;
        if (last_known && last_known.profiles) {
          var profile_cutoff = last_known.profiles.getTime( );
          profiles = all_profiles.filter(function (profile) {
            return new Date(profile.created_at || profile.startDate).getTime( ) > profile_cutoff;
          });
        } else {
          // No destination bookmark: sync only the newest profile document.
          profiles = all_profiles.slice( ).sort(function (a, b) {
            return new Date(b.created_at || b.startDate) - new Date(a.created_at || a.startDate);
          }).slice(0, 1);
        }
        console.log("FETCHED", profiles.length, "new profiles from", all_profiles.length, "total");

        return { entries: filtered, devicestatus: devicestatus, treatments: treatments, profiles: profiles };
      });
    },
    transformGlucose (data) {
      var entries = (data.entries || []).map(strip_server_fields);
      var devicestatus = (data.devicestatus || []).map(strip_server_fields);
      var treatments = (data.treatments || []).map(strip_server_fields);
      var profiles = (data.profiles || []).map(strip_server_fields);
      console.log("TRANSFORMING NIGHTSCOUT DATA:", entries.length, "entries,", devicestatus.length, "devicestatus,", treatments.length, "treatments,", profiles.length, "profiles");
      return { entries, devicestatus, treatments, profiles };
    }
  };

  // ---------------------------------------------------------------- V3 ----
  // Incremental sync cursors keyed by v3 collection name, holding source
  // srvModified epoch values. Committed only after a successful persist
  // (align_to_glucose runs post-persist), so failed frames refetch.
  var cursors = { entries: null, treatments: null, devicestatus: null, profile: null };
  var pending_cursors = null;
  var historySupported = true;
  var profile_bootstrapped = false;

  function seed_cursors (last_known) {
    var two_days_ago = new Date( ).getTime( ) - (2 * 24 * 60 * 60 * 1000);
    if (cursors.entries == null) {
      cursors.entries = (last_known && last_known.entries) ? last_known.entries.getTime( ) : two_days_ago;
    }
    if (cursors.treatments == null) {
      cursors.treatments = (last_known && last_known.treatments) ? last_known.treatments.getTime( ) : two_days_ago;
    }
    if (cursors.devicestatus == null) {
      cursors.devicestatus = (last_known && last_known.devicestatus) ? last_known.devicestatus.getTime( ) : two_days_ago;
    }
    if (cursors.profile == null) {
      cursors.profile = (last_known && last_known.profiles) ? last_known.profiles.getTime( ) : two_days_ago;
    }
  }

  function max_srv_modified (docs, floor) {
    return docs.reduce(function (newest, doc) {
      var stamp = doc.srvModified || doc.date;
      return (stamp && stamp > newest) ? stamp : newest;
    }, floor);
  }

  function fetch_history (col, since, headers) {
    var docs = [ ];
    function page (cursor, pages) {
      return http.get('/api/v3/' + col + '/history/' + cursor, { params: { limit: HISTORY_LIMIT }, headers }).then((resp) => {
        var batch = unwrapV3(resp) || [ ];
        docs = docs.concat(batch);
        if (batch.length === HISTORY_LIMIT && pages < MAX_HISTORY_PAGES) {
          var next = max_srv_modified(batch, cursor);
          if (next > cursor) {
            return page(next, pages + 1);
          }
        }
        return docs;
      });
    }
    return page(since, 1);
  }

  function fallback_query (col, since, headers) {
    // Older v3 builds without history support: plain filtered search.
    var query = { 'date$gt': since, 'limit': HISTORY_LIMIT, 'sort$desc': 'date' };
    return http.get('/api/v3/' + col, { params: query, headers }).then((resp) => {
      return unwrapV3(resp) || [ ];
    });
  }

  var implV3 = {
    authFromCredentials (creds, settings) {
      // Always get a proper token: v3 data reads require a JWT.
      if (params.token) return Promise.resolve(params.token);
      console.log("V3: Getting authentication token");
      return token_from_subjects( ).catch(err => {
        console.error("❌ V3 authFromCredentials FAILED:", err.message || err);
        throw err;
      });
    },
    sessionFromAuth (accessToken, settings) {
      if (accessToken && accessToken.readable) {
        return Promise.reject(new Error("V3 requires JWT bearer token"));
      }
      return jwt_session_from_token(accessToken).catch((err) => {
        console.error("❌ V3 SESSION ERROR:", err.message || err);
        throw err;
      });
    },
    align_to_glucose (last_known) {
      // Persist succeeded: commit the cursors advanced by the last fetch.
      if (pending_cursors) {
        Object.assign(cursors, pending_cursors);
        pending_cursors = null;
        profile_bootstrapped = true;
      }
      return align_to_glucose_shared(last_known);
    },
    dataFromSesssion (session, last_known) {
      if (!session || !session.bearer) {
        // v3 detected but no JWT obtainable (e.g. open-read site without an
        // API secret): downgrade permanently to the v1 data path.
        console.warn("⚠️  V3 requires a bearer token; downgrading to API V1 data path");
        detectedApiVersion = 'v1';
        return implV1.dataFromSesssion(session, last_known);
      }
      seed_cursors(last_known);
      var headers = auth_headers(session);
      var names = [ 'entries', 'treatments', 'devicestatus', 'profile' ];
      // No destination bookmark for profiles yet: history cursors cannot
      // reach far enough back (servers reject very old lastModified values),
      // so fetch the newest profile document via a plain search once.
      var bootstrap_profile = !profile_bootstrapped && !(last_known && last_known.profiles);

      function tolerant (col, fetch_promise) {
        // Entries are the primary loop and must fail loudly; the other
        // collections degrade to an empty fetch (cursor stays put).
        if (col === 'entries') return fetch_promise;
        return fetch_promise.catch(function (err) {
          var status = err.response && err.response.status;
          console.warn("⚠️  Skipping", col, "this cycle (HTTP", status, "):", err.message || err);
          return [ ];
        });
      }

      function fetch_all (fetcher) {
        return Promise.all(names.map(function (col) { return tolerant(col, fetcher(col)); })).then(function (results) {
          var batch = { };
          var next_cursors = { };
          names.forEach(function (col, ix) {
            // History includes deletions; skip tombstones.
            var docs = (results[ix] || [ ]).filter(function (doc) { return doc.isValid !== false; });
            batch[col === 'profile' ? 'profiles' : col] = docs;
            next_cursors[col] = max_srv_modified(results[ix] || [ ], cursors[col]);
            console.log("FETCHED", docs.length, "new", col, "documents via v3 (cursor", cursors[col], "->", next_cursors[col], ")");
          });
          pending_cursors = next_cursors;
          return batch;
        });
      }

      function newest_profile ( ) {
        return http.get('/api/v3/profile', { params: { limit: 1, 'sort$desc': 'date' }, headers }).then((resp) => {
          return unwrapV3(resp) || [ ];
        });
      }

      if (!historySupported) {
        return fetch_all(function (col) {
          if (col === 'profile' && bootstrap_profile) return newest_profile( );
          return fallback_query(col, cursors[col], headers);
        });
      }

      return http.get('/api/v3/lastModified', { headers }).then((resp) => {
        var result = unwrapV3(resp) || { };
        var collections = result.collections || { };
        return fetch_all(function (col) {
          if (col === 'profile' && bootstrap_profile) return newest_profile( );
          if (collections[col] != null && collections[col] <= cursors[col]) {
            // Nothing changed since our cursor: skip the round-trip.
            return Promise.resolve([ ]);
          }
          return fetch_history(col, cursors[col], headers);
        });
      }).catch((err) => {
        var status = err.response && err.response.status;
        if (status === 404 || status === 405) {
          console.warn("⚠️  v3 lastModified/history unsupported (HTTP", status, "); using filtered queries");
          historySupported = false;
          return fetch_all(function (col) {
            if (col === 'profile' && bootstrap_profile) return newest_profile( );
            return fallback_query(col, cursors[col], headers);
          });
        }
        console.error("❌ V3 DATA FETCH ERROR:", status, err.message || err);
        throw err;
      });
    },
    transformGlucose (data) {
      // Normalize v3 documents to v1-compatible shape for the output side.
      var entries = (data.entries || []).map(function (entry) {
        var out = Object.assign({ }, entry);
        if (!out.dateString && out.date) {
          out.dateString = new Date(out.date).toISOString( );
        }
        return strip_server_fields(out);
      });
      function backfill_created_at (doc) {
        var out = Object.assign({ }, doc);
        if (!out.created_at && out.date) {
          out.created_at = new Date(out.date).toISOString( );
        }
        return strip_server_fields(out);
      }
      var treatments = (data.treatments || []).map(backfill_created_at);
      var devicestatus = (data.devicestatus || []).map(backfill_created_at);
      var profiles = (data.profiles || []).map(backfill_created_at);
      console.log("TRANSFORMING NIGHTSCOUT V3 DATA:", entries.length, "entries,", devicestatus.length, "devicestatus,", treatments.length, "treatments,", profiles.length, "profiles");
      return { entries, devicestatus, treatments, profiles };
    }
  };

  // ----------------------------------------------------------- facade ----
  function current ( ) {
    return detectedApiVersion === 'v3' ? implV3 : implV1;
  }

  var impl = {
    authFromCredentials (creds, settings) {
      return detectApiVersion( ).then(function ( ) {
        return current( ).authFromCredentials(creds, settings);
      });
    },
    sessionFromAuth (accessToken, settings) {
      return detectApiVersion( ).then(function ( ) {
        return current( ).sessionFromAuth(accessToken, settings);
      });
    },
    align_to_glucose (last_known) {
      return current( ).align_to_glucose(last_known);
    },
    dataFromSesssion (session, last_known) {
      return detectApiVersion( ).then(function ( ) {
        return current( ).dataFromSesssion(session, last_known);
      });
    },
    transformGlucose (data) {
      return current( ).transformGlucose(data);
    }
  };

  function tracker_for ( ) {
    try {
      var AxiosTracer = require('../trace-axios');
      if (typeof AxiosTracer !== 'function') {
        console.warn("⚠️ AxiosTracer loaded but not a function:", typeof AxiosTracer);
        return null;
      }
      var tracker = AxiosTracer(http);
      if (!tracker || typeof tracker.getGeneratedHar !== 'function') {
        console.warn("⚠️ AxiosTracer not properly initialized - getGeneratedHar not available");
        return null;
      }
      console.log("✅ AxiosTracer initialized successfully for Bun");
      return tracker;
    } catch (err) {
      console.error("❌ Failed to initialize AxiosTracer:", err.message || err);
      return null;
    }
  }

  function generate_driver (builder) {
    builder.support_session({
      authenticate: impl.authFromCredentials,
      authorize: impl.sessionFromAuth,
      // refresh: impl.refreshSession,
      delays: {
        REFRESH_AFTER_SESSSION_DELAY: 28800000,
        EXPIRE_SESSION_DELAY: 28800000,
      }
    });

    builder.register_loop('NightscoutEntries', {
      tracker: tracker_for,
      frame: {
        impl: impl.dataFromSesssion,
        align_schedule: impl.align_to_glucose,
        transform: impl.transformGlucose,
        backoff: {
          // wait ten seconds before retrying to get data
          interval_ms: 10000
        },
        // only try 3 times to get data
        maxRetries: 3
      },
      // expect new data 5 minutes after last success
      expected_data_interval_ms: 5 * 60 * 1000,
      backoff: {
        // wait 2.5 minutes * 2^attempt
        interval_ms: 2.5 * 60 * 1000
      },
    });
    return builder;
  };
  impl.generate_driver = generate_driver;
  return impl;
}

nightscoutSource.validate = function validate_inputs (input) {
  var ok = false;
  var errors = [ ];
  var config = {
    url: input.sourceEndpoint,
    apiSecret: input.sourceApiSecret || '',
    apiVersion: (input.sourceApiVersion || process.env.CONNECT_SOURCE_API_VERSION || 'auto').toLowerCase( ),
  };
  if (!config.url) {
    errors.push({desc: "Nightscout Connect source needed. CONNECT_SOURCE_ENDPOINT must be a url.", err: new Error(input.sourceEndpoint) } );
  }
  if ([ 'auto', 'v1', 'v3' ].indexOf(config.apiVersion) < 0) {
    errors.push({desc: "CONNECT_SOURCE_API_VERSION must be one of auto, v1, v3.", err: new Error(config.apiVersion) } );
  }
  ok = errors.length == 0;
  config.kind = ok ? 'nightscout' : 'disabled';
  return { ok, errors, config }

}

module.exports = nightscoutSource;
