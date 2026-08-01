
const { createMachine, Machine, actions, interpret, spawn  } = require('xstate');
var testImpl = require('../testable_driver');
var axios = require('axios');
var builder = require('../lib/builder');
var sources = require('../lib/sources');
var outputs = require('../lib/outputs');

function sidecarLoop (input, output) {
  
  // everything known for output
  // output must be passed into builder, before generate_driver is
  // called.
  var endpoint = outputs(output)(output, axios);
  var make = builder({ output: endpoint });
  // var make = builder({ output });

  // select an available input source implementation based on env
  // variables/config
  var driver = sources(input);
  console.log("INPUT PARAMS", input);
  var impl = driver(input, axios);
  // var impl = testImpl.fakeFrame({ }, axios);

  impl.generate_driver(make);

  var built = make( );
  // console.log("BUILDER OUTPUT", built);
  console.log("BUILDER OUTPUT", JSON.stringify(built, null, 2));
  return built;

}

function main (argv) {
  console.log("STARTING forever", { source: argv.source });
  var output = {
    name: 'nightscout'
  , url: argv.nightscoutEndpoint
  , apiSecret: argv.apiSecret
  , apiVersion: argv.nightscoutApiVersion
  , token: argv.nightscoutToken
  };
  console.log("CONFIGURED OUTPUT", { name: output.name, url: output.url, apiVersion: output.apiVersion, hasSecret: !!output.apiSecret, hasToken: !!output.token });
  var input = { kind: argv.source, url: argv.sourceEndpoint, apiSecret: argv.sourceApiSecret, apiVersion: argv.sourceApiVersion };
  console.log("CONFIGURED INPUT", { kind: input.kind, url: input.url, apiVersion: input.apiVersion, hasSecret: !!input.apiSecret });

  var things = sidecarLoop(input, output);
  console.log(things);
  var actor = interpret(things);
  actor.start( );
  actor.send({type: 'START'});

}


module.exports.command = 'forever [hint]';
module.exports.describe = 'Runs as a background server forever.'
module.exports.builder = (yargs) => yargs
  .option('source', { alias: 'hint', describe: 'source input', default: 'default', choices: Object.keys(sources.kinds)})
  .option('sourceApiVersion', { describe: 'Nightscout API version for the source (auto|v1|v3)', choices: ['auto', 'v1', 'v3'] })
  .option('nightscoutApiVersion', { describe: 'Nightscout API version for the output (v1|v3)', choices: ['v1', 'v3'] })
  .option('nightscoutToken', { describe: 'Nightscout access token (subject) used for output writes' })
module.exports.handler = main;
