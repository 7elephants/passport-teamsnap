/**
 * Module dependencies.
 */
var util = require('util')
    , OAuth2Strategy = require('passport-oauth2')
    , InternalOAuthError = require('passport-oauth2').InternalOAuthError
    , collectionJSON = require('collection-json');


/**
 * `Strategy` constructor.
 *
 * The Teamsnap authentication strategy authenticates requests by delegating to
 * Teamsnap using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `apiVersion`    (optional) the Teamsnap API version to use (Only '3' currently). Default is '3'.
 *   - `clientID`      your Teamsnap application's app key found in the App Console
 *   - `clientSecret`  your Teamsnap application's app secret
 *   - `callbackURL`   URL to which Dropbox will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new TeamsnapStrategy({
 *         clientID: 'yourAppKey',
 *         clientSecret: 'yourAppSecret'
 *         callbackURL: 'https://www.example.net/auth/dropbox-teamsnap/callback',
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  
  var supportedApiVersions = ['3'],
      defaultOptionsByApiVersion = {
        3: {
          profileURL:'https://api.teamsnap.com/v3/me',
          authorizationURL: 'https://auth.teamsnap.com/oauth/authorize',
          tokenURL: 'https://auth.teamsnap.com/oauth/token',
          scopeSeparator: ' ',
          customHeaders: {
            'Content-Type': 'application/json'
          }
        }
      };

  options = options || {};
  if (!verify) { throw new TypeError('TeamsnapStrategy requires a verify callback'); }
  if (!options.clientID) { throw new TypeError('TeamsnapStrategy requires a clientID option'); }

  if (options.apiVersion != null && supportedApiVersions.indexOf(options.apiVersion.toString()) === -1) {
    throw new Error('Unsupported Teamsnap API version. Supported versions is "3".');
  }

  this._apiVersion = options.apiVersion || '3';
  this._profileURL = options.profileURL || defaultOptionsByApiVersion[this._apiVersion].profileURL;

  options.authorizationURL = options.authorizationURL || defaultOptionsByApiVersion[this._apiVersion].authorizationURL;
  options.tokenURL = options.tokenURL || defaultOptionsByApiVersion[this._apiVersion].tokenURL;
  
  options.scopeSeparator = options.scopeSeparator || defaultOptionsByApiVersion[this._apiVersion].scopeSeparator;
  options.customHeaders = options.customHeaders || defaultOptionsByApiVersion[this._apiVersion].customHeaders;

  OAuth2Strategy.call(this, options, verify);
  this.name = 'teamsnap';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Use a different method of the OAuth2Strategy for making an external request to the selected Teamsnap API version.
 * Currently API v3 supports only POST requests for retrieving the user's profile.
 *
 * @param {String} accessToken
 * @param {Function} callback
 * @private
 */
Strategy.prototype._retrieveUserProfile = function(accessToken, callback) {
  this._oauth2._request('GET', this._profileURL,
        {'Authorization': this._oauth2.buildAuthHeader(accessToken) }, 'null', accessToken, callback);
};

/**
 * Retrieve user profile from Teamsnap.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `teamsnap`
 *   - `id`               the user's unique Teamsnap ID
 *   - `displayName`      a name that can be used directly to represent the name of a user's Dropbox account
 *   - `emails`           the user's email address
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._retrieveUserProfile(accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var profile = { provider: 'teamsnap' };
      var json = JSON.parse(body);
      
      profile._raw = body;
      profile._json = json;
      
      if (json) {
        collectionJSON.parse(body, function(error,collection) {
          if (!error) {
            profile.id = collection.items['id'];
            profile.displayName = collection.items['first_name'] + ' ' + collection.items['last_name'];

            profile.name = {
              familyName: collection.items['last_name'],
              givenName: collection.items['first_name'],
              middleName: ''
            };
            profile.emails = [{ value: collection.items['email'] }];

            done(null, profile);
          } else {
            done(error, profile);
          }
        });
      } else {
        done(null,profile);
      }
    } catch(e) {
      done(e);
    }
  }.bind(this));
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
