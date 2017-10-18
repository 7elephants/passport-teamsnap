# Passport-Teamsnap
[Passport](http://passportjs.org/) strategy for authenticating with [Teamsnap](https://www.teamsnap.com/)
using the OAuth 2.0 API.

This module lets you authenticate using Dropbox in your Node.js applications.
By plugging into Passport, Dropbox authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install
    $ npm install passport-teamsnap

## Usage
### Configure Strategy

The Teamsnap authentication strategy authenticates users using a Teamsnap account
and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a API version, client ID, client secret, and callback URL. The library
defaults to version 3 of Teamsnap's API.

    passport.use(new TeamsnapStrategy({
        apiVersion: '3',
        clientID: TEAMSNAP_CLIENT_ID,
        clientSecret: TEAMSNAP_CLIENT_SECRET,
        callbackURL: "https://www.example.net/auth/dropbox-oauth2/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ providerId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

### Authenticate Requests
Use `passport.authenticate()`, specifying the `'teamsnap'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/teamsnap',
      passport.authenticate('teamsnap'));

    app.get('/auth/teamsnap/callback', 
      passport.authenticate('teamsnap', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Examples
Examples not yet provided

## Tests
Tests not yet provided


## Prior work
This strategy is based on Jared Hanson's GitHub strategy for passport: [Jared Hanson](http://github.com/jaredhanson) and specifically his work on [passport-oauth2](http://github.com/jaredhanson/passport-oauth2)

## Credits and License
express-sslify is licensed under the MIT license. If you'd like to be informed about new projects follow  [@TheSumOfAll](http://twitter.com/TheSumOfAll/).

Copyright (c) 2017 Andrew Steiger