# passport-metamask

[Passport](http://passportjs.org/) strategy for authenticating with a username
and password.

This module lets you authenticate using the Metamask Chrome extension.  By plugging into Passport, authentication through the Ethereum wallet extension can be
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-metamask

## Usage

#### How this strategy is different

Most authentication is client initiated.  The metamask strategy is, by necessity, server initiated.
The metamask client proves the identity of a client by providing a cryptographic signature with
the client's private key.  The reason it must be server initiated is that when you sign a message that
signature is good for that message forever.  Any interception of that signature would make that message
unreliable.  Therefore, a unique message must be used for every login and the server must choose
the message to make sure that clients could not fool the server with a captured signature.

#### Configure Strategy

The metamask authentication strategy authenticates users using a message from the server and
a signature from the user's private key.  The strategy can use a `postVerifyGetInfo` callback,
which accepts the verified public address and calls `done` providing user information.

    passport.use(new MetamaskStrategy(
      function(address, done) {
        User.findOne({ address: address }, function (err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false); }
          return done(null, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'metamask'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.post('/login',
      passport.authenticate('local', { failureRedirect: '/login' }),
      function(req, res) {
        res.redirect('/');
      });

## Examples
(not done yet)  
For complete, working examples, refer to the multiple [examples](https://github.com/jaredhanson/passport-local/tree/master/examples) included.

## Tests
(not done yet)  
    $ npm install
    $ npm test

## Credits

  - [Jacob Gostylo](http://github.com/jgostylo)
  Thanks to:
  - [Jared Hanson](http://github.com/jaredhanson)
  for local-strategy on which this was based

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2018 Jacob Gostylo <[http://github.com/jgostylo](http://github.com/jgostylo)>
Copyright (c) 2011-2014 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
