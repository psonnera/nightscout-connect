var { test, expect } = require('bun:test');

var nightscoutRestAPI = require('../lib/outputs/nightscout');

function fakeAxios ( ) {
  var calls = [ ];
  var scripts = { };
  function key (method, path) {
    return method.toUpperCase( ) + ' ' + path;
  }
  function respond (config) {
    var method = (config.method || 'get').toLowerCase( );
    var path = config.url;
    calls.push({ method: method, url: path, params: config.params, data: config.data, headers: config.headers });
    var queue = scripts[key(method, path)];
    var scripted = (queue && queue.length) ? queue.shift( ) : { status: 200, data: [ ] };
    if (scripted.status >= 400) {
      var allowed = config.validateStatus && config.validateStatus(scripted.status);
      if (!allowed) {
        var err = new Error("Request failed with status code " + scripted.status);
        err.response = scripted;
        return Promise.reject(err);
      }
    }
    return Promise.resolve(scripted);
  }
  var instance = {
    request: respond
  , get: function (path, config) { return respond(Object.assign({ }, config, { method: 'get', url: path })); }
  , post: function (path, data, config) { return respond(Object.assign({ }, config, { method: 'post', url: path, data: data })); }
  };
  return {
    create: function ( ) { return instance; }
  , calls: calls
  , script: function (method, path, responses) { scripts[key(method, path)] = responses.slice( ); }
  };
}

var CONFIG_V1 = { url: 'https://dest.example.com/', apiSecret: 'hunter22-1234', apiVersion: 'v1' };
var CONFIG_V3 = { url: 'https://dest.example.com/', apiSecret: 'hunter22-1234', apiVersion: 'v3' };

test('v3 record_batch posts one document at a time with app and type defaults', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v3/entries', [
    { status: 201, data: { status: 201, identifier: 'a' } }
  , { status: 200, data: { status: 200, isDeduplication: true, deduplicatedIdentifier: 'b' } }
  , { status: 201, data: { status: 201, identifier: 'c' } }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  await record_batch.gap_for( );
  var entries = [
    { sgv: 100, dateString: '2026-08-01T10:00:00.000Z' }
  , { sgv: 105, date: 1754042700000 }
  , { sgv: 110, dateString: '2026-08-01T10:10:00.000Z' }
  ];
  await record_batch({ entries: entries });
  var posts = axios.calls.filter(function (c) { return c.method === 'post' && c.url === '/api/v3/entries'; });
  expect(posts.length).toBe(3);
  posts.forEach(function (post) {
    expect(post.data.app).toBe('nightscout-connect');
    expect(post.data.type).toBe('sgv');
    expect(typeof post.data.date).toBe('number');
  });
});

test('v3 profiles are written to /api/v3/profile', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v3/profile', [
    { status: 201, data: { status: 201, identifier: 'p1' } }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  await record_batch.gap_for( );
  await record_batch({ profiles: [ { defaultProfile: 'Default', created_at: '2026-07-01T00:00:00.000Z' } ] });
  var posts = axios.calls.filter(function (c) { return c.method === 'post' && c.url === '/api/v3/profile'; });
  expect(posts.length).toBe(1);
});

test('v3 total write failure rejects so the loop backs off', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v3/entries', [
    { status: 500, data: { } }
  , { status: 500, data: { } }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  await record_batch.gap_for( );
  var entries = [
    { sgv: 100, dateString: '2026-08-01T10:00:00.000Z' }
  , { sgv: 105, dateString: '2026-08-01T10:05:00.000Z' }
  ];
  await expect(record_batch({ entries: entries })).rejects.toThrow(/failed to write/);
});

test('v1 devicestatus is chunked at 50 per POST', async function ( ) {
  var axios = fakeAxios( );
  var record_batch = nightscoutRestAPI(CONFIG_V1, axios);
  await record_batch.gap_for( );
  var statuses = [ ];
  for (var i = 0; i < 120; i++) {
    statuses.push({ device: 'openaps://rig', created_at: new Date(1754042700000 + i * 1000).toISOString( ) });
  }
  await record_batch({ devicestatus: statuses });
  var posts = axios.calls.filter(function (c) { return c.method === 'post' && c.url === '/api/v1/devicestatus.json'; });
  expect(posts.length).toBe(3);
  expect(posts[0].data.length).toBe(50);
  expect(posts[1].data.length).toBe(50);
  expect(posts[2].data.length).toBe(20);
});

test('v1 413 splits the batch in half and retries', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v1/devicestatus.json', [
    { status: 413, data: { } }
  , { status: 200, data: [ ] }
  , { status: 200, data: [ ] }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V1, axios);
  await record_batch.gap_for( );
  var statuses = [ ];
  for (var i = 0; i < 40; i++) {
    statuses.push({ device: 'openaps://rig', created_at: new Date(1754042700000 + i * 1000).toISOString( ) });
  }
  await record_batch({ devicestatus: statuses });
  var posts = axios.calls.filter(function (c) { return c.method === 'post' && c.url === '/api/v1/devicestatus.json'; });
  expect(posts.length).toBe(3);
  expect(posts[1].data.length).toBe(20);
  expect(posts[2].data.length).toBe(20);
});

test('gap_for on v3 uses /api/v3/lastModified', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v3/lastModified', [
    { status: 200, data: { status: 200, result: { collections: { entries: 1754042700000, treatments: 1754042100000, profile: 1750000000000 } } } }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  var bookmark = await record_batch.gap_for( );
  expect(bookmark.entries).toEqual(new Date(1754042700000));
  expect(bookmark.treatments).toEqual(new Date(1754042100000));
  expect(bookmark.profiles).toEqual(new Date(1750000000000));
});

test('gap_for on v3 falls back to a latest-entry probe when lastModified is missing', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v3/lastModified', [ { status: 404, data: { } } ]);
  axios.script('GET', '/api/v3/entries', [
    { status: 200, data: { status: 200, result: [ { date: 1754042700000, sgv: 100 } ] } }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  var bookmark = await record_batch.gap_for( );
  expect(bookmark.entries).toEqual(new Date(1754042700000));
  var search = axios.calls.filter(function (c) { return c.method === 'get' && c.url === '/api/v3/entries'; })[0];
  expect(search.params.limit).toBe(1);
  expect(search.params['sort$desc']).toBe('date');
});

test('gap_for on v1 probes entries and profile', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v1/entries.json', [
    { status: 200, data: [ { dateString: '2026-08-01T10:05:00.000Z', sgv: 100 } ] }
  ]);
  axios.script('GET', '/api/v1/profile.json', [
    { status: 200, data: [ { created_at: '2026-07-01T00:00:00.000Z' } ] }
  ]);
  var record_batch = nightscoutRestAPI(CONFIG_V1, axios);
  var bookmark = await record_batch.gap_for( );
  expect(bookmark.entries).toEqual(new Date('2026-08-01T10:05:00.000Z'));
  expect(bookmark.profiles).toEqual(new Date('2026-07-01T00:00:00.000Z'));
});

test('bookmark advances to the newest entry regardless of batch order', async function ( ) {
  var axios = fakeAxios( );
  var record_batch = nightscoutRestAPI(CONFIG_V1, axios);
  await record_batch.gap_for( );
  // ascending order, as v3 history returns them
  var entries = [
    { sgv: 100, dateString: '2026-08-01T10:00:00.000Z' }
  , { sgv: 105, dateString: '2026-08-01T10:05:00.000Z' }
  , { sgv: 110, dateString: '2026-08-01T10:10:00.000Z' }
  ];
  var bookmark = await record_batch({ entries: entries });
  expect(bookmark.entries).toEqual(new Date('2026-08-01T10:10:00.000Z'));
});

test('record_batch exposes the v3 api for single-document operations', function ( ) {
  var axios = fakeAxios( );
  var record_batch = nightscoutRestAPI(CONFIG_V3, axios);
  expect(typeof record_batch.api.collection).toBe('function');
  expect(typeof record_batch.api.collection('entries').read).toBe('function');
  expect(typeof record_batch.api.collection('entries').remove).toBe('function');
});
