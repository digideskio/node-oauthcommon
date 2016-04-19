'use strict';

var PromiseA = require('bluebird');

module.exports.inject = function (getControllers, app/*, pkgConf, pkgDeps*/) {
  var scoper = require('app-scoped-ids');

  //var jwsUtils = require('./lib/jws-utils').create(signer);
  var CORS = require('connect-cors');
  var cors = CORS({ credentials: true, headers: [
    'X-Requested-With'
  , 'X-HTTP-Method-Override'
  , 'Content-Type'
  , 'Accept'
  , 'Authorization'
  ], methods: [ "GET", "POST", "PATCH", "PUT", "DELETE" ] });

  // Allows CORS access to API with ?access_token=
  // TODO Access-Control-Max-Age: 600
  // TODO How can we help apps handle this? token?
  // TODO allow apps to configure trustedDomains, auth, etc

  //
  // Generic Session / Login / Account Routes
  //
  function parseAccessToken(req, opts) {
    var token;
    var parts;
    var scheme;
    var credentials;

    if (req.headers && req.headers.authorization) {
      // Works for all of Authorization: Bearer {{ token }}, Token {{ token }}, JWT {{ token }}
      parts = req.headers.authorization.split(' ');

      if (parts.length !== 2) {
        return PromiseA.reject(new Error("malformed Authorization header"));
      }

      scheme = parts[0];
      credentials = parts[1];

      if (-1 !== (opts && opts.schemes || ['token', 'bearer']).indexOf(scheme.toLowerCase())) {
        token = credentials;
      }
    }

    if (req.body && req.body.access_token) {
      if (token) { PromiseA.reject(new Error("token exists in header and body")); }
      token = req.body.access_token;
    }

    // TODO disallow query with req.method === 'GET'
    // NOTE: the case of DDNS on routers requires a GET and access_token
    // (cookies should be used for protected static assets)
    if (req.query && req.query.access_token) {
      if (token) { PromiseA.reject(new Error("token already exists in either header or body and also in query")); }
      token = req.query.access_token;
    }

    /*
    err = new Error(challenge());
    err.code = 'E_BEARER_REALM';

    if (!token) { return PromiseA.reject(err); }
    */

    return PromiseA.resolve(token);
  }

  /* Scenario
   * https://github.com/OAuth3/SPEC/wiki/token
   *
   * Let's say that the app is Imgur.com and the provider is DaplieConnect.com
   *   iss - The issuer (iss) is DaplieConnect.com
   *   pub - The fingerprint (pub) of an approved DaplieConnect.com pub/priv keypair
   *   sub - The subject (sub) is either DaplieConnect.com or perhaps a 3rd party such as Facebook.com
   *   aud - The audience (aud) is Imgur.com,sub.imgur.com (or whomever else )
   *   typ - The type (typ) is 'credentials' if the purpose is login, or it may be something else
   *   data - application-specific data
   *
   *
   * How can a token be used?
   *
   * [iss, aud, pub] A consumer may trust a token only if it trusts and verifies (iss, aud, pub)
   *
   *   1) addressed to the audience
   *      (normally imgur.com and imgurpartner.com will trust tokens addressed to imgur.com)
   *
   *   2) signed by the issuer
   *      (normally imgur.com and imgurpartner.com will trust tokens signed by facebook.com
   *      with a public key that matches the pub fingerprint)
   *
   * [typ, sub] A consumer may use a token only in accordance with it's attributes (typ, sub)
   *
   *   1) a 'credentials' token type would be different from a 'purchase' or 'dns' or 'milkshake token'
   *
   *   2) the subject is type specific
   *
   */
  function getClient(req, token, priv, Controllers) {
    if (!token) {
      token = req.oauth3.token;
    }

    // if the app is imgur
    //var issuer = token.iss;
    // TODO this needs to be a fingerprint, not the whole key
    var pubkey = (token.pub || token.k);
    var cacheId = '_' + pubkey + 'Client';

    if (priv[cacheId]) {
      return PromiseA.resolve(priv[cacheId]);
    }

    // TODO could get client directly by token.app (id of client)
    //console.log('[oauthcommon] token', token);
    priv[cacheId] = Controllers.Clients.login(null, pubkey, null, {
      id: token.k               // TODO client id or key id?
      // (TODO implicit?) req.headers.origin, req.headers.referer, (NOT req.headers.host)
    , clientUri: token.iss      // token, clientUri,

      // tokens may not be shared across different sites
    , origin: req.headers.origin
    , referer: req.headers.referer
    , isDeviceClient: !(req.headers.origin || req.headers.referer) || undefined
    }).then(function (apiKey) {
      if (!apiKey) {
        return PromiseA.reject(new Error("Client no longer valid"));
      }

      priv[cacheId + 'Key'] = apiKey;
      priv[cacheId] = apiKey.oauthClient;

      return apiKey.oauthClient;
    });

    return priv[cacheId];
  }

  function getAccountsByLogin(req, token, priv, Controllers, loginId, decrypt) {
    return getClient(req, req.oauth3.token, priv, Controllers).then(function (oauthClient) {
      if (decrypt) {
        loginId = scoper.unscope(loginId, oauthClient.secret);
      }

      return Controllers.models.AccountsLogins.find({ loginId: loginId }).then(function (accounts) {
        return PromiseA.all(accounts.map(function (obj) {
          //console.log('DEBUG AccountsLogins', obj);
          return Controllers.models.Accounts.get(obj.accountId).then(function (account) {
            account.appScopedId = scoper.scope(account.id, oauthClient.secret);
            return account;
          });
        }));
      });
    });
  }

  function getAccountsByArray(req, Controllers, arr) {
    return PromiseA.all(arr.map(function (accountId) {
      return Controllers.models.Accounts.get(accountId.id || accountId);
    }));
  }

  function getAccounts(req, token, priv, Controllers) {
    if (!token) {
      token = req.oauth3.token;
    }

    var err;

    if (priv._accounts) {
      return PromiseA.resolve(priv._accounts);
    }

    if ((req.oauth3.token.idx || req.oauth3.token.usr) && ('password' === req.oauth3.token.grt || 'login' === req.oauth3.token.as)) {
      priv._accounts = getAccountsByLogin(req, req.oauth3.token, priv, Controllers, (req.oauth3.token.idx || req.oauth3.token.usr), !!req.oauth3.token.idx);
    } else if (req.oauth3.token.axs && req.oauth3.token.axs.length || req.oauth3.token.acx) {
      priv._accounts = getAccountsByArray(req, Controllers, req.oauth3.token.axs && req.oauth3.token.axs.length && req.oauth3.token.axs || [req.oauth3.token.acx]);
    } else {
      err = new Error("neither login nor accounts were specified");
      err.code = "E_NO_AUTHZ";
      priv._accounts = PromiseA.reject(err);
    }

    return priv._accounts.then(function (accounts) {
      priv._accounts = accounts;

      return accounts;
    });
  }

  function getLoginIds(req, token, priv, Controllers) {
    if (!token) {
      token = req.oauth3.token;
    }

    var cacheId = '_loginIds';

    if (priv[cacheId]) {
      return PromiseA.resolve(priv[cacheId]);
    }

    // TODO
    // this ends up defeating part of the purpose of JWT (few database calls)
    // perhaps the oauthClient secret should be sent, encrypted with a master key,
    // with the request? Or just mash the oauthClient secret with the loginId
    // and encrypt with the master key?
    priv[cacheId] = getClient(req, token, priv, Controllers).then(function (oauthClient) {
      var loginIds = [];

      if (token.usr) {
        loginIds.push(token.usr);
      }
      token.ids.forEach(function (id) {
        loginIds.push(id);
      }).filter(function (id) { return id; });
      token.ixs.forEach(function (idx) {
        loginIds.push(scoper.unscope(idx, oauthClient.secret));
      }).filter(function (id) { return id; });

      priv[cacheId] = loginIds;

      return loginIds;
    });

    return priv[cacheId];
  }

  function getLogins(req, token, priv, Controllers) {
    if (!token) {
      token = req.oauth3.token;
    }

    var mcacheId = '_logins';

    if (priv[mcacheId]) {
      return priv[mcacheId];
    }

    priv[mcacheId] = getLoginIds(req, token, priv).then(function (loginIds) {
      var logins = [];

      loginIds.forEach(function (id) {
        var cacheId = '_' + id + 'Login';

        if (priv[cacheId]) {
          return PromiseA.resolve(priv[cacheId]);
        }

        // DB.Logins.get(hashId)
        logins.push(Controllers.Logins.rawGet(id).then(function (login) {
          priv[cacheId] = login;

          return login;
        }));
      });

      return PromiseA.all(logins);
    });

    return priv[mcacheId];
  }

  function attachOauth3(req, res, next) {
    var privs = {};
    req.oauth3 = {};

    return parseAccessToken(req).then(function (token) {
      if (!token) {
        next();
        return;
      }

      return getControllers(req.experienceId).then(function (Controllers) {

        var jwt = require('jsonwebtoken');
        var data = jwt.decode(token);
        var err;

        if (!data) {
          err = new Error('not a json web token');
          err.code = 'E_NOT_JWT';
          res.send({
            error: err.code
          , error_description: err.message
          , error_url: 'https://oauth3.org/docs/errors#' + (err.code || 'E_UNKNOWN_EXCEPTION')
          });
          // PromiseA.reject(err);
          return;
        }

        req.oauth3.encodedToken = token;
        req.oauth3.token = data;

        req.oauth3.getLoginIds = function (token) {
          return getLoginIds(req, (token || req.oauth3.token), privs, Controllers);
        };

        req.oauth3.getLogins = function (token) {
          return getLogins(req, (token || req.oauth3.token), privs, Controllers);
        };

        // TODO modify prototypes?
        req.oauth3.getClient = function (token) {
          return getClient(req, (token || req.oauth3.token), privs, Controllers);
        };

        // TODO req.oauth3.getAccountIds
        req.oauth3.getAccounts = function (token) {
          return getAccounts(req, (token || req.oauth3.token), privs, Controllers);
        };

        req.oauth3.verifyAsync = function (encodedToken) {
          return Controllers.Signer.verifyAsync(req.experienceId, (encodedToken || req.oauth3.encodedToken));
        };

        req.oauth3.rescope = function (acx) {
          var scoper = require('app-scoped-ids');

          return req.oauth3.getClient().then(function (oauthClient) {
            var id = scoper.unscope(acx, oauthClient.secret);

            return scoper.scope(id, Controllers.Oauth3RootClient.secret);
          });
        };

        next();
      });
    });
  }

  app.use('/', cors);

  app.use('/', attachOauth3);
};
