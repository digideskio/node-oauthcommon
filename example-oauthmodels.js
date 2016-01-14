'use strict';

module.exports.create = function (conf/*, app, pkgConf, pkgDeps*/) {
  var PromiseA = require('bluebird');
  var inProcessDbCache = {};
  var inProcessCache = {};
  var createClientFactory = require('sqlite3-cluster/client').createClientFactory;
  var dir = require('./example-directives');

  function getAppScopedDb(experienceId) {
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

    getAppScopedDb.then(function (stuff) {
      var sqlStore = stuff.sqlStore;
      var clientFactory = stuff.clientFactory;

      inProcessCache[experienceId] = mq.wrap(sqlStore, dir).then(function (models) {
        //return require('oauthclient-microservice/lib/sign-token').create(models.PrivateKey).init().then(function (signer) {
          var CodesCtrl = require('authcodes').create(models.Codes);
          /* models = { Logins, Verifications } */
          var LoginsCtrl = require('authentication-microservice/lib/logins').create({}, CodesCtrl, models);
          /* models = { ApiKeys, OauthClients } */
          var ClientsCtrl = require('oauthclient-microservice/lib/oauthclients').createController({}, models);

          return {
            Db: stuff.sqlStore
          , Codes: CodesCtrl
          , Logins: LoginsCtrl
          , Clients: ClientsCtrl
          , SqlFactory: clientFactory
          , models: models
          };
        //});
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
