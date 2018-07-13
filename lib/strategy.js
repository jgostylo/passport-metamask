/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , lookup = require('./utils').lookup
  , sigUtil = require('eth-sig-util');
  // , tokenGenerator = require('uuid-token-generator');


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, postVerifyGetInfo) {

  if (typeof options == 'function') {
    postVerifyGetInfo = options;
    options = {};
  }
  //if (!postVerifyInfo) { throw new TypeError('LocalStrategy requires a verify callback'); }

  if (options == null){
    options = {};
  }

  if (postVerifyGetInfo){
    this._postVerifyGetInfo = postVerifyGetInfo;
  }

  this._payload = options.payload || 'payload';
  this._signature = options.signature || 'signature';
  this._sessionID = options.sessionID || 'sessionID';

  passport.Strategy.call(this);
  this.name = 'metamask';
  this._passReqToCallback = options.passReqToCallback;
  this._nonce = {};
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Set the session based nonce for this authentication request.
 *
 * @param {String} sessionId
 * @param {String} nonce
 * @api protected
 */
Strategy.prototype.setnonce = function(sessionID, nonce){
  this._nonce[sessionID] = nonce;
}

/**
 * Delete the session based nonce for this authentication request.
 *
 * @param {String} sessionId
 * @api protected
 */
Strategy.prototype.deletenonce = function(sessionID){
  delete this._nonce[sessionID];
}

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var payload = lookup(req.body, this._payload) || lookup(req.query, this._payload);
  var signature = lookup(req.body, this._signature) || lookup(req.query, this._signature);
  var sessionID = lookup(req.body, this._sessionID) || lookup(req.query, this._sessionID);

  if (!payload || !signature) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }

  if (!sessionID && !self._passReqToCallback){
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    console.log("This was a success");
    self.success(user, info);
  }

  try {
    if (self._passReqToCallback) {
      this.verify(req, payload, signature, verified);
    } else {
      this.verify(sessionID, payload, signature, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};

/**
 * Verify the signature and the nonce against the session.
 *
 * @param {Object} req
 * @param {String} payload
 * @param {String} signature
 * @param {Function} verified
 * @api protected
 */
Strategy.prototype.verify = function(session, payload, signature, verified){
  var sessionID;
  if (typeof session == 'Object') {
    sessionID = session.id;
  } else {
    sessionID = session;
  }

  // do not need to surround in try, catch because caller does that
  var jsonData = JSON.parse(payload);
  var checkAddress = jsonData.address.toLowerCase();
  var checkNonce = jsonData.nonce;

  if (checkNonce != this._nonce[sessionID]){
    verified(null, null, "The nonce given is not the nonce for this session");
    return;
  }

  var msgToVerify = {'data': payload, 'sig': signature};
  var returnAddress = sigUtil.recoverPersonalSignature(msgToVerify);

  if (returnAddress != checkAddress){
    verified(null, null, "The address did not match the signature");
    return;
  }
  if (this._postVerifyGetInfo){
    this._postVerifyGetInfo(checkAddress, verified);
  } else {
    verified(null, checkAddress, "Authentication successful");
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
