var { test, expect, beforeEach } = require('bun:test');

var createV3Client = require('../lib/nightscout/api-v3');

// Fake axios: records every request and replies from a scripted queue keyed
// by "METHOD path". Unscripted requests get a 200 with empty body.
function fakeAxios ( ) {
  var calls = [ ];
  var scripts = { };
  function key (method, path) {
    return method.toUpperCase( ) + ' ' + path;
  }
  function respond (config) {
    var method = (config.method || 'get');
    var path = config.url;
    calls.push({ method: method.toLowerCase( ), url: path, params: config.params, data: config.data, headers: config.headers });
    var queue = scripts[key(method, path)];
    var scripted = (queue && queue.length) ? queue.shift( ) : { status: 200, data: { } };
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

var BASE = { url: 'https://ns.example.com/', apiSecret: 'hunter22-1234' };

test('unwrap returns result for v3 envelopes and passes v1 arrays through', function ( ) {
  var axios = fakeAxios( );
  var client = createV3Client(BASE, axios);
  expect(client.unwrap({ data: { status: 200, result: [ 1, 2 ] } })).toEqual([ 1, 2 ]);
  expect(client.unwrap({ data: [ 3, 4 ] })).toEqual([ 3, 4 ]);
  expect(client.unwrap({ data: { status: 'ok' } })).toEqual({ status: 'ok' });
});

test('authorize memoizes the JWT until near expiry', async function ( ) {
  var axios = fakeAxios( );
  var exp = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/request/tok-en', [
    { status: 200, data: { token: 'jwt-1', iat: exp - 3600, exp: exp } }
  , { status: 200, data: { token: 'jwt-2', iat: exp - 3600, exp: exp } }
  ]);
  var client = createV3Client(Object.assign({ token: 'tok-en' }, BASE), axios);
  await client.collection('entries').search({ limit: 1 });
  await client.collection('entries').search({ limit: 1 });
  var authCalls = axios.calls.filter(function (c) { return c.url.indexOf('/authorization/request/') >= 0; });
  expect(authCalls.length).toBe(1);
  var dataCalls = axios.calls.filter(function (c) { return c.url === '/api/v3/entries'; });
  expect(dataCalls[0].headers['Authorization']).toBe('Bearer jwt-1');
});

test('expired session re-authorizes', async function ( ) {
  var axios = fakeAxios( );
  var past = Math.floor(Date.now( ) / 1000) - 10;
  var future = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/request/tok-en', [
    { status: 200, data: { token: 'jwt-old', iat: past - 60, exp: past } }
  , { status: 200, data: { token: 'jwt-new', iat: future - 3600, exp: future } }
  ]);
  var client = createV3Client(Object.assign({ token: 'tok-en' }, BASE), axios);
  await client.collection('entries').search({ });
  await client.collection('entries').search({ });
  var authCalls = axios.calls.filter(function (c) { return c.url.indexOf('/authorization/request/') >= 0; });
  expect(authCalls.length).toBe(2);
});

test('401 invalidates the session and retries exactly once', async function ( ) {
  var axios = fakeAxios( );
  var exp = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/request/tok-en', [
    { status: 200, data: { token: 'jwt-1', exp: exp, iat: exp - 3600 } }
  , { status: 200, data: { token: 'jwt-2', exp: exp, iat: exp - 3600 } }
  ]);
  axios.script('POST', '/api/v3/treatments', [
    { status: 401, data: { } }
  , { status: 201, data: { status: 201, identifier: 'abc' } }
  ]);
  var client = createV3Client(Object.assign({ token: 'tok-en' }, BASE), axios);
  var result = await client.collection('treatments').create({ eventType: 'Note' });
  expect(result.created).toBe(true);
  expect(result.identifier).toBe('abc');

  // Two consecutive 401s must reject rather than loop.
  axios.script('POST', '/api/v3/treatments', [
    { status: 401, data: { } }
  , { status: 401, data: { } }
  ]);
  await expect(client.collection('treatments').create({ eventType: 'Note' })).rejects.toThrow();
});

test('create classifies 201 create vs 200 dedup', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v3/entries', [
    { status: 201, data: { status: 201, identifier: 'new-id', lastModified: 111 } }
  , { status: 200, data: { status: 200, isDeduplication: true, deduplicatedIdentifier: 'dup-id' } }
  ]);
  var client = createV3Client(BASE, axios);
  var first = await client.collection('entries').create({ sgv: 120 });
  expect(first).toMatchObject({ created: true, deduplicated: false, identifier: 'new-id', httpStatus: 201 });
  var second = await client.collection('entries').create({ sgv: 120 });
  expect(second).toMatchObject({ created: false, deduplicated: true, identifier: 'dup-id', httpStatus: 200 });
});

test('create classifies immutable-field 400 as a dedup conflict', async function ( ) {
  var axios = fakeAxios( );
  axios.script('POST', '/api/v3/treatments', [
    { status: 400, data: { status: 400, message: 'Field utcOffset cannot be modified by the client' } }
  ]);
  var client = createV3Client(Object.assign({ token: 'tok-en' }, BASE), axios);
  var exp = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/request/tok-en', [
    { status: 200, data: { token: 'jwt', exp: exp, iat: exp - 3600 } }
  ]);
  var result = await client.collection('treatments').create({ eventType: 'Temp Basal', date: 123 });
  expect(result.deduplicated).toBe(true);
  expect(result.conflict).toBe(true);
  expect(result.created).toBe(false);
});

test('read resolves null on 404/410, doc on 200', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v3/entries/gone', [ { status: 410, data: { } } ]);
  axios.script('GET', '/api/v3/entries/missing', [ { status: 404, data: { } } ]);
  axios.script('GET', '/api/v3/entries/found', [ { status: 200, data: { status: 200, result: { sgv: 99 } } } ]);
  var client = createV3Client(BASE, axios);
  expect(await client.collection('entries').read('gone')).toBeNull();
  expect(await client.collection('entries').read('missing')).toBeNull();
  expect(await client.collection('entries').read('found')).toEqual({ sgv: 99 });
});

test('update/patch/remove/history hit the right endpoints', async function ( ) {
  var axios = fakeAxios( );
  var client = createV3Client(BASE, axios);
  await client.collection('treatments').update('id-1', { insulin: 1 });
  await client.collection('treatments').patch('id-1', { insulin: 2 });
  await client.collection('treatments').remove('id-1', { permanent: true });
  await client.collection('treatments').history(123456);
  var urls = axios.calls.map(function (c) { return c.method + ' ' + c.url; });
  expect(urls).toContain('put /api/v3/treatments/id-1');
  expect(urls).toContain('patch /api/v3/treatments/id-1');
  expect(urls).toContain('delete /api/v3/treatments/id-1');
  expect(urls).toContain('get /api/v3/treatments/history/123456');
});

test('lastModified unwraps collections', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v3/lastModified', [
    { status: 200, data: { status: 200, result: { srvDate: 1700000009999, collections: { entries: 1700000000000 } } } }
  ]);
  var client = createV3Client(BASE, axios);
  var result = await client.lastModified( );
  expect(result.collections.entries).toBe(1700000000000);
});

test('without token, a writer subject is bootstrapped from the API secret', async function ( ) {
  var axios = fakeAxios( );
  var exp = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/subjects', [
    { status: 200, data: [ ] }
  , { status: 200, data: [ { name: 'nightscout-connect-writer', accessToken: 'boot-tok' } ] }
  ]);
  axios.script('GET', '/api/v2/authorization/request/boot-tok', [
    { status: 200, data: { token: 'jwt-boot', exp: exp, iat: exp - 3600 } }
  ]);
  var client = createV3Client(BASE, axios);
  await client.collection('entries').search({ });
  var subjectPost = axios.calls.filter(function (c) { return c.method === 'post' && c.url === '/api/v2/authorization/subjects'; });
  expect(subjectPost.length).toBe(1);
  expect(subjectPost[0].data.name).toBe('nightscout-connect-writer');
  expect(subjectPost[0].data.roles).toEqual([ 'admin' ]);
  expect(subjectPost[0].headers['API-SECRET']).toBe(createV3Client.encode_api_secret(BASE.apiSecret));
  var search = axios.calls.filter(function (c) { return c.url === '/api/v3/entries'; })[0];
  expect(search.headers['Authorization']).toBe('Bearer jwt-boot');
});

test('failed subject bootstrap falls back to API-SECRET header and stops retrying', async function ( ) {
  var axios = fakeAxios( );
  axios.script('GET', '/api/v2/authorization/subjects', [
    { status: 404, data: { } }
  ]);
  var client = createV3Client(BASE, axios);
  await client.collection('entries').search({ });
  await client.collection('entries').search({ });
  var searches = axios.calls.filter(function (c) { return c.url === '/api/v3/entries'; });
  expect(searches.length).toBe(2);
  searches.forEach(function (call) {
    expect(call.headers['API-SECRET']).toBe(createV3Client.encode_api_secret(BASE.apiSecret));
  });
  // bootstrap attempted once, not per request
  var subjectGets = axios.calls.filter(function (c) { return c.method === 'get' && c.url === '/api/v2/authorization/subjects'; });
  expect(subjectGets.length).toBe(1);
});

test('token can come from ?token= in the url', async function ( ) {
  var axios = fakeAxios( );
  var exp = Math.floor(Date.now( ) / 1000) + 3600;
  axios.script('GET', '/api/v2/authorization/request/query-token', [
    { status: 200, data: { token: 'jwt-q', exp: exp, iat: exp - 3600 } }
  ]);
  var client = createV3Client({ url: 'https://ns.example.com/?token=query-token', apiSecret: 'hunter22-1234' }, axios);
  await client.collection('entries').search({ });
  var call = axios.calls.filter(function (c) { return c.url === '/api/v3/entries'; })[0];
  expect(call.headers['Authorization']).toBe('Bearer jwt-q');
});
