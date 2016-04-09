'use strict';

module.exports.create = function (conf/*, app, pkgConf, pkgDeps*/) {
  var PromiseA = require('bluebird');
  var inProcessDbCache = {};
  var inProcessCache = {};
  var createClientFactory = require('sqlite3-cluster/client').createClientFactory;
  var dir = require('./example-directives');
  var jwt;

  function getAppScopedFactories(experienceId) {
    if (inProcessDbCache[experienceId]) {
      return PromiseA.resolve(inProcessDbCache[experienceId]);
    }

    var path = require('path');
    // TODO how can we encrypt this?
    var systemFactory = createClientFactory({
      // TODO only complain if the values are different
        dirname: path.join(__dirname, '..', '..', 'var') // TODO info.conf

      , prefix: 'org.oauth3.' // 'com.example.'
      //, prefix: appname.replace(/\//g, ':') // 'com.example.'
      //, dbname: 'cluster'
      , suffix: ''
      , ext: '.sqlite3'
      , sock: conf.sqlite3Sock
      , ipcKey: conf.ipcKey
    });
    var clientFactory = createClientFactory({
    // TODO only complain if the values are different
      dirname: path.join(__dirname, '..', '..', 'var') // TODO info.conf
    , algorithm: 'aes'
    , bits: 128
    , mode: 'cbc'

    , prefix: 'org.oauth3.' // 'com.example.'
    //, dbname: 'config'
    , suffix: ''
    , ext: '.sqlcipher'
    , sock: conf.sqlite3Sock
    , ipcKey: conf.ipcKey
    });

    inProcessDbCache[experienceId] = systemFactory.create({
      init: true
    //, key: '00000000000000000000000000000000'
    , dbname: experienceId // 'com.example.'
    }).then(function (sqlStore) {
      return {
        sqlStore: sqlStore
      , systemFactory: systemFactory
      , clientFactory: clientFactory
      };
    });

    return inProcessDbCache[experienceId];
  }

  function getAppScopedControllers(experienceId) {
    var mq = require('masterquest-sqlite3');

    if (inProcessCache[experienceId]) {
      return PromiseA.resolve(inProcessCache[experienceId]);
    }

    inProcessCache[experienceId] = getAppScopedFactories(experienceId).then(function (stuff) {
      var sqlStore = stuff.sqlStore;
      var clientFactory = stuff.clientFactory;

      return mq.wrap(sqlStore, dir).then(function (models) {
        var CodesCtrl = require('authcodes').create(models.Codes);
        /* models = { Logins, Verifications } */
        var LoginsCtrl = require('authentication-microservice/lib/logins').create({}, CodesCtrl, models);
        /* models = { ApiKeys, OauthClients } */
        var ClientsCtrl = require('oauthclient-microservice/lib/oauthclients').createController({}, models);

        var Controllers = {
          Db: models // stuff.sqlStore
        , Codes: CodesCtrl
        , Logins: LoginsCtrl
        , Clients: ClientsCtrl
        , SqlFactory: clientFactory
        , models: models
        };

        var config = {};

        var OauthClients = require('oauthclient-microservice/lib/oauthclients').createController(config, models);

        return OauthClients.getOrCreateClient(config, {
          experienceId: experienceId
        , keyUrlId: experienceId
        }).then(function (oauthClient) {
          //return require('oauthclient-microservice/lib/sign-token').create(models.PrivateKey).init().then(function (signer) {
          //});

          Controllers.Oauth3RootClient = oauthClient;
          Controllers.Oauth3RootKey = oauthClient.apiKeys.filter(function (apiKey) {
            return apiKey.url === experienceId;
          })[0];
          Controllers.Signer = {
            sign: function (data) {
              jwt = jwt || PromiseA.promisifyAll(require('jsonwebtoken'));

              data.iss = Controllers.Oauth3RootClient.url;
              // k for 'key of client'
              data.k = data.k || Controllers.Oauth3RootKey.id;
              data.sub = '/api/org.oauth3.keypairs/' + Controllers.Oauth3RootKey.id + '.pub';

              return PromiseA.resolve(jwt.sign(data, Controllers.Oauth3RootKey.priv, { algorithm: 'RS256' }));
            }
          , verifyAsync: function (experienceId, token) {
              jwt = jwt || PromiseA.promisifyAll(require('jsonwebtoken'));

              var decoded = jwt.decode(token, { complete: true });
              var err;

              if (!decoded) {
                err = new Error("Invalid JWT");
                err.code = "E_INVALID_JWT";
                return PromiseA.reject(err);
              }

              // TODO enable trusting of other issuers
              if ((decoded.payload.iss || decoded.payload.app) !== experienceId) {
                console.error('issuer does not match', (decoded.payload.iss || decoded.payload.app), experienceId);
                return null;
              }

              return jwt.verifyAsync(token, Controllers.Oauth3RootKey.pub, { algorithm: 'RS256' /*, ignoreExpiration: true */});
            }
          };

          return Controllers;
        });
      });
    }).then(function (ctrls) {
      inProcessCache[experienceId] = ctrls;

      return ctrls;
    });

    return inProcessCache[experienceId];
  }

  return {
    getControllers: getAppScopedControllers
  };
};
