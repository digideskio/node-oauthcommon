'use strict';

module.exports.create = function (conf/*, app, pkgConf, pkgDeps*/) {
  var PromiseA = require('bluebird');
  var inProcessCache = {};
  var createClientFactory = require('sqlite3-cluster/client').createClientFactory;
  var dir = [
    { tablename: 'codes'
    , idname: 'uuid'
    , indices: ['createdAt']
    }
  , { tablename: 'logins' // coolaj86, coolaj86@gmail.com, +1-317-426-6525
    , idname: 'hashId'
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'type', 'node']
    //, immutable: false
    }
  , { tablename: 'verifications'
    , idname: 'hashId' // hash(date + node)
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'nodeId']
    //, immutable: true
    }
  , { tablename: 'secrets'
    , idname: 'hashId' // hash(node + secret)
    , indices: ['createdAt']
    //, immutable: true
    }
  , { tablename: 'recoveryNodes' // just for 1st-party logins
    , idname: 'hashId' //
      // TODO how transmit that something should be deleted / disabled?
    , indices: ['createdAt', 'updatedAt', 'loginHash', 'recoveryNode', 'deleted']
    }

    //
    // Accounts
    //
  , { tablename: 'accounts_logins'
    , idname: 'id' // hash(accountId + loginId)
    , indices: ['createdAt', 'revokedAt', 'loginId', 'accountId']
    }
  , { tablename: 'accounts'
    , idname: 'id' // crypto random id? or hash(name) ?
    , unique: ['name']
    , indices: ['createdAt', 'updatedAt', 'deletedAt', 'name', 'displayName']
    }

    //
    // OAuth3
    //
  , { tablename: 'private_key'
    , idname: 'id'
    , indices: ['createdAt']
    }
  , { tablename: 'oauth_clients'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'accountId']
    , hasMany: ['apiKeys'] // TODO
    , belongsTo: ['account']
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'api_keys'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'oauthClientId', 'url']
    , belongsTo: ['oauthClient'] // TODO pluralization
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'tokens' // note that a token functions as a session
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'expiresAt', 'revokedAt', 'oauthClientId', 'loginId', 'accountId']
    }
  , { tablename: 'grants'
    , idname: 'id' // sha256(scope + oauthClientId + (accountId || loginId))
    , indices: ['createdAt', 'updatedAt', 'oauthClientId', 'loginId', 'accountId']
    }
  ];

  function getAppScopedControllers(experienceId) {
    if (inProcessCache[experienceId]) {
      return PromiseA.resolve(inProcessCache[experienceId]);
    }

    var mq = require('masterquest-sqlite3');
    var path = require('path');
    // TODO how can we encrypt this?
    var systemFactory = createClientFactory({
      // TODO only complain if the values are different
        algorithm: 'aes'
      , bits: 128
      , mode: 'cbc'
      , dirname: path.join(__dirname, '..', '..', 'var') // TODO info.conf
      //, prefix: appname.replace(/\//g, ':') // 'com.example.'
      //, dbname: 'cluster'
      , suffix: ''
      , ext: '.sqlcipher'
      , sock: conf.sqlite3Sock
      , ipcKey: conf.ipcKey
    });
    var clientFactory = createClientFactory({
    // TODO only complain if the values are different
      dirname: path.join(__dirname, '..', '..', 'var') // TODO info.conf
    , prefix: 'com.oauth3' // 'com.example.'
    //, dbname: 'config'
    , suffix: ''
    , ext: '.sqlite3'
    , sock: conf.sqlite3Sock
    , ipcKey: conf.ipcKey
    });

    inProcessCache[experienceId] = systemFactory.create({
      init: true
    //, key: '00000000000000000000000000000000'
    , dbname: experienceId // 'com.example.'
    }).then(function (sqlStore) {
      //var db = factory.
      return mq.wrap(sqlStore, dir).then(function (models) {
        //return require('oauthclient-microservice/lib/sign-token').create(models.PrivateKey).init().then(function (signer) {
          var CodesCtrl = require('authcodes').create(models.Codes);
          /* models = { Logins, Verifications } */
          var LoginsCtrl = require('authentication-microservice/lib/logins').create({}, CodesCtrl, models);
          /* models = { ApiKeys, OauthClients } */
          //var ClientsCtrl = require('oauthclient-microservice/lib/oauthclients').createController({}, models, signer);

          return {
            Codes: CodesCtrl
          , Logins: LoginsCtrl
          //, Clients: ClientsCtrl
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
