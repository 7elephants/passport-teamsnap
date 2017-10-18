var TeamsnapStrategy = require('../lib/strategy')
  , AuthorizationError = require('../lib/errors/authorizationerror')
  , TokenError = require('../lib/errors/tokenerror')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');

describe('TeamsnapStrategy', function() {
  
  describe('constructed', function() {
    
    describe('with normal options', function() {
      var strategy = new TeamsnapStrategy({
          clientID: '4843bda735f1bec9051dd466f2e6a76ef6e2563b51ea4af9a0342216fe9a12eb',
          clientSecret: 'd34ddc7e9b1fa6c87065e6104036e1944f2a7ac208701bf13b652d78998d340b'
        }, function() {});
    
      it('should be named teamsnap', function() {
        expect(strategy.name).to.equal('teamsnap');
      });
    }); // with normal options
    
    describe('without a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new TeamsnapStrategy({
            clientID: '4843bda735f1bec9051dd466f2e6a76ef6e2563b51ea4af9a0342216fe9a12eb',
            clientSecret: 'd34ddc7e9b1fa6c87065e6104036e1944f2a7ac208701bf13b652d78998d340b'
          });
        }).to.throw(TypeError, 'TeamsnapStrategy requires a verify callback');
      });
    }); // without a verify callback
    
    describe('without a clientID option', function() {
      it('should throw', function() {
        expect(function() {
          new TeamsnapStrategy({
            clientSecret: 'secret'
          }, function() {});
        }).to.throw(TypeError, 'TeamsnapStrategy requires a clientID option');
      });
    }); // without a clientID option
    
    describe('without a clientSecret option', function() {
      it('should not throw', function() {
        expect(function() {
          new TeamsnapStrategy({
            clientID: '4843bda735f1bec9051dd466f2e6a76ef6e2563b51ea4af9a0342216fe9a12eb'
          }, function() {});
        }).to.not.throw();
      });
    }); // without a clientSecret option
    
    describe('with only a verify callback', function() {
      it('should throw', function() {
        expect(function() {
          new TeamsnapStrategy(function() {});
        }).to.throw(TypeError, 'TeamsnapStrategy requires a clientID option');
      });
    }); // with only a verify callback
    
  }); // constructed
  
});
