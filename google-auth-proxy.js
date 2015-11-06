var https = require('https');
var http = require('http');
var Cookies = require( "cookies" );
var config = require('./config.json');
var url = require('url');
var proxy = require('./proxy.js');
var oauth = require('./oauth.js');
var fs = require('fs');
var Keygrip = require('keygrip');
var keys = Keygrip(config.cookie.keys);

var options = {
  key: fs.readFileSync(config.server.ssl.keyFile),
  cert: fs.readFileSync(config.server.ssl.crtFile)
};

var server = https.createServer(options);

var handleRequest = function( url, cookies, notFound, redirect, forbidden, proxyReq ) {
  proxy.detectProxy( url, function( err, proxyServer, host ) {
    // 1. If no such proxy exists, then 404
    if( err ) {
      notFound(err);
      return;
    } 
    var email = cookies.get(config.cookie.name, { signed: true } );
    // 2. If no cookie or invalid, redirect for auth
    if( !email ) {
      redirect();
      return;
    } 
    // 3. if not authorised, give 403
    if( config.oauth.validUsers.indexOf( email ) == -1 ) {
      forbidden(email);
      return;
    }
    // 4. now proxy
    console.log( 'Proxying request   ' + email + ':' + url + ' => ' + host );
    proxyReq();
  });
};

server.on('request', function(req, res) {
  
  var cookies = new Cookies(req,res,keys);
  
  var badRequest = function(err) {
    console.log(err);
    res.writeHead(403, {'Content-Type': 'text/plain'});
    res.write('Bad request');
    res.end();
  };
  
  var redirect = function(loc) {
    console.log('Redirecting to '+loc);
    res.writeHead(302, {'Location': loc});
    res.end();
  };
  
  var notFound = function(err) {
    console.log( err );
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.write('The page you are looking for is not found');
    res.end();
  };
  
  var forbidden = function(err) {
    console.log( err );
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.write('You are not authorised to access this page');
    res.end();
  }
  
  var reqUrl = url.parse(req.url, true);
  if( !reqUrl ) {
    badRequest('Failed to parse request URL');
    return;
  }
  
  if( reqUrl.pathname == config.oauth.callbackPath ) {
    oauth.action(reqUrl.query.code, reqUrl.query.state, function( err, email, path ) {
      if( err ) {
        badRequest(err);
        return;
      }
      cookies.set(config.cookie.name, email, { signed: true, secureProxy: true, overwrite: true, maxAge: config.cookie.maxAge });
      redirect(path);
    });
    return;
  } 
  
  // normal path processing
  proxy.detectProxy( req.url, function( err, proxyServer, host ) {
    // 1. If no such proxy exists, then 404
    if( err ) {
      notFound(err);
      return;
    } 
    var email = cookies.get(config.cookie.name, { signed: true } );
    // 2. If no cookie or invalid, redirect for auth
    if( !email ) {
      redirect(oauth.authUrl(reqUrl.path));
      return;
    } 
    // 3. if not authorised, give 403
    if( config.oauth.validUsers.indexOf( email ) == -1 ) {
      forbidden('User not authorised: '+email);
      return;
    }
    // 4. now proxy
    console.log( 'Proxying request   ' + email + ':' + req.url + ' => ' + host );
    proxyServer.web(req,res);
  });
    
});

server.on('upgrade', function (req, socket, head) {
  var cookies = new Cookies(req,{},keys);
  
  var end = function(err) {
    console.log(err);
    socket.end();
  }
  
  proxy.detectProxy( req.url, function( err, proxyServer, host ) {
    //1. If no proxy exists, close socket
    if( err ) {
      end( err );
      return;
    } 
    var email = cookies.get(config.cookie.name, { signed: true } );
    //2. if no email in cookie, close socket
    if( !email ) {
      end('No authorisation cookie for websocket');
      return;
    } 
    // 3. if not authorised, close socket
    if( config.oauth.validUsers.indexOf( email ) == -1 ) {
      end('User not authorised: '+email);
      return;
    }
    // 4. now proxy
    console.log( 'Proxying websocket ' + email + ':' + req.url + ' => ' + host );
    proxyServer.ws(req, socket, head);
    
  });
});

server.listen(process.env.PORT || config.server.port || 3000, process.env.IP || "0.0.0.0", function() {
  var addr = server.address();
  console.log("Google auth proxy server listening at", addr.address + ":" + addr.port);
});
