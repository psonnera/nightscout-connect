
var qs = require('qs');
var url = require('url');
var crypto = require('crypto');

var software = require('../../package.json');
var user_agent_string = [software.name, `${software.name}@${software.version}`, 'Nightscout API', software.homepage].join(', ');

function encode_api_secret (plain) {
  var shasum = crypto.createHash('sha1');
  shasum.update(plain);
  return shasum.digest('hex').toLowerCase( );
}

// Reusable Nightscout API v3 client.
// opts: { url, apiSecret, token }
//   - token: a Nightscout access token (subject "name-hash"); may also be
//     supplied as ?token= in opts.url. When present, requests authenticate
//     with a JWT obtained from /api/v2/authorization/request/<token>
//     (authorization lives under v2 even for v3 data access).
//   - apiSecret: fallback auth, sent as hashed API-SECRET header.
// axios: the axios module (or a compatible object with .create).
function createV3Client (opts, axios) {
  var endpoint = url.parse(opts.url);
  var baseURL = url.format({
    protocol: endpoint.protocol || 'https'
  , host: endpoint.host
  , pathname: endpoint.pathname
  });
  var params = qs.parse(endpoint.query || '');
  var token = opts.token || params.token || null;
  var apiHash = opts.apiSecret ? encode_api_secret(opts.apiSecret) : null;
  var http = axios.create ? axios.create({
    baseURL
  , headers: { 'User-Agent': user_agent_string }
  }) : axios;

  var session = null;         // { bearer, exp } exp in epoch ms
  var sessionPromise = null;  // in-flight authorization request
  var jwt_unavailable = false; // subject bootstrap failed; stop retrying

  var JWT_SAFETY_MARGIN_MS = 60000;
  var SUBJECT_NAME = 'nightscout-connect-writer';

  // v3 endpoints only honor JWTs, never the API-SECRET header. When no
  // access token is configured, use the API secret (admin) to find or
  // create a dedicated subject, mirroring the source driver's reader
  // subject bootstrap.
  function ensure_token ( ) {
    if (token) {
      return Promise.resolve(token);
    }
    if (!apiHash) {
      return Promise.reject(new Error("No access token or API secret configured for v3 authorization"));
    }
    var authURL = '/api/v2/authorization/subjects';
    var headers = { 'API-SECRET': apiHash };
    function find_subject (body) {
      return (body || [ ]).filter(function (item) { return item.name == SUBJECT_NAME; }).pop( );
    }
    return http.get(authURL, { headers }).then(function (resp) {
      var match = find_subject(resp.data);
      if (match) {
        token = match.accessToken;
        return token;
      }
      // NB: the field is 'roles' (plural); 'role' is silently ignored and
      // yields a permissionless subject whose JWT gets 403 on writes.
      var subject = {
        name: SUBJECT_NAME,
        roles: [ 'admin' ],
        notes: 'Used by nightscout-connect to write synced data over API v3.'
      };
      return http.post(authURL, subject, { headers }).then(function ( ) {
        return http.get(authURL, { headers }).then(function (resp) {
          var match = find_subject(resp.data);
          if (match) {
            token = match.accessToken;
            return token;
          }
          return Promise.reject(new Error("Could not create v3 subject " + SUBJECT_NAME));
        });
      });
    });
  }

  function authorize ( ) {
    if (session && Date.now( ) < session.exp - JWT_SAFETY_MARGIN_MS) {
      return Promise.resolve(session);
    }
    if (sessionPromise) {
      return sessionPromise;
    }
    sessionPromise = ensure_token( ).then(function (accessToken) {
      return http.get('/api/v2/authorization/request/' + accessToken);
    }).then(function (resp) {
      var body = resp.data || { };
      session = {
        bearer: body.token
      , exp: (body.exp || 0) * 1000
      , info: body
      };
      sessionPromise = null;
      return session;
    }).catch(function (err) {
      sessionPromise = null;
      throw err;
    });
    return sessionPromise;
  }

  function invalidate ( ) {
    session = null;
    sessionPromise = null;
  }

  function headers_for ( ) {
    if ((token || apiHash) && !jwt_unavailable) {
      return authorize( ).then(function (sess) {
        return { 'Authorization': ['Bearer', sess.bearer].join(' ') };
      }).catch(function (err) {
        if (token) throw err;
        // Could not bootstrap a subject from the secret (e.g. authorization
        // API disabled): fall back to the API-SECRET header once and stop
        // retrying the bootstrap. Some proxied/legacy setups honor it.
        console.warn("⚠️  v3 JWT bootstrap failed (" + (err.message || err) + "); falling back to API-SECRET header");
        jwt_unavailable = true;
        return { 'API-SECRET': apiHash };
      });
    }
    if (apiHash) {
      return Promise.resolve({ 'API-SECRET': apiHash });
    }
    return Promise.resolve({ });
  }

  // v3 wraps payloads in { status, result }; v1 (and some v3 auth endpoints)
  // return the payload bare. Handle both.
  function unwrap (resp) {
    var data = resp && resp.data;
    if (data && typeof data === 'object' && typeof data.status === 'number' && 'result' in data) {
      return data.result;
    }
    return data;
  }

  function request (method, path, options, is_retry) {
    options = options || { };
    return headers_for( ).then(function (headers) {
      return http.request({
        method: method
      , url: path
      , params: options.params
      , data: options.data
      , headers: Object.assign({ }, options.headers, headers)
      , validateStatus: options.validateStatus
      });
    }).catch(function (err) {
      // JWT may have been revoked or expired server-side: refresh once.
      if (!is_retry && token && err.response && err.response.status === 401) {
        invalidate( );
        return request(method, path, options, true);
      }
      throw err;
    });
  }

  function identifier_from_location (resp) {
    var location = resp && resp.headers && (resp.headers.location || resp.headers.Location);
    if (!location) return undefined;
    return location.split('/').pop( );
  }

  function lastModified ( ) {
    // -> { srvDate, collections: { entries, treatments, devicestatus, profile } } (epoch ms)
    return request('get', '/api/v3/lastModified').then(unwrap);
  }

  function version ( ) {
    return request('get', '/api/v3/version').then(unwrap);
  }

  function status ( ) {
    return request('get', '/api/v3/status').then(unwrap);
  }

  function collection (name) {
    var base = '/api/v3/' + name;
    return {
      // params: limit, skip, sort or sort$desc, fields, and field operators
      // such as date$gt, created_at$gte, etc.
      search: function search (search_params) {
        return request('get', base, { params: search_params }).then(unwrap);
      }
    , create: function create (doc) {
        // v3 create is single-document: 201 = created, 200 = deduplicated.
        return request('post', base, {
          data: doc
        , validateStatus: function (s) { return s === 200 || s === 201; }
        }).then(function (resp) {
          var body = (resp.data && typeof resp.data === 'object') ? resp.data : { };
          var dedup = resp.status === 200 || !!body.isDeduplication;
          return {
            created: !dedup
          , deduplicated: dedup
          , identifier: body.deduplicatedIdentifier || body.identifier || identifier_from_location(resp)
          , lastModified: body.lastModified
          , httpStatus: resp.status
          };
        }).catch(function (err) {
          // Dedup matched an existing document but an immutable field
          // (utcOffset, app, ...) differs from the stored copy. The document
          // exists; retrying can never succeed. Report it as a dedup with a
          // conflict marker instead of an error.
          var resp = err.response;
          var message = resp && resp.data && resp.data.message;
          if (resp && resp.status === 400 && /cannot be modified by the client/.test(message || '')) {
            return {
              created: false
            , deduplicated: true
            , conflict: true
            , conflictMessage: message
            , httpStatus: resp.status
            };
          }
          throw err;
        });
      }
    , read: function read (identifier) {
        // 404 (never existed) and 410 (deleted) both resolve to null.
        return request('get', base + '/' + identifier, {
          validateStatus: function (s) { return s === 200 || s === 404 || s === 410; }
        }).then(function (resp) {
          if (resp.status !== 200) return null;
          return unwrap(resp);
        });
      }
    , update: function update (identifier, doc) {
        return request('put', base + '/' + identifier, { data: doc }).then(unwrap);
      }
    , patch: function patch (identifier, doc) {
        return request('patch', base + '/' + identifier, { data: doc }).then(unwrap);
      }
    , remove: function remove (identifier, remove_params) {
        // remove_params: { permanent: true } to skip the soft-delete trash.
        return request('delete', base + '/' + identifier, { params: remove_params }).then(unwrap);
      }
    , history: function history (last_modified_ms, history_params) {
        var path = (last_modified_ms != null) ? base + '/history/' + last_modified_ms : base + '/history';
        return request('get', path, { params: history_params }).then(unwrap);
      }
    };
  }

  return {
    baseURL: baseURL
  , token: token
  , authorize: authorize
  , invalidate: invalidate
  , headers_for: headers_for
  , unwrap: unwrap
  , request: request
  , lastModified: lastModified
  , version: version
  , status: status
  , collection: collection
  , http: http
  };
}

createV3Client.encode_api_secret = encode_api_secret;
module.exports = createV3Client;
