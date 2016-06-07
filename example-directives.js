'use strict';

module.exports = [
  //
  // Logins & AuthCodes
  //
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
  , indices: ['createdAt', 'updatedAt', 'oauthClientId', 'loginId', 'accountId', 'scope']
  }
];
