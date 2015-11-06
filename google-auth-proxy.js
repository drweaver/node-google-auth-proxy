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

var handleRequest = function( url, cookies, stop, redirect, proxyReq ) {
  proxy.detectProxy( url, function( err, proxyServer, host ) {
    // 1. If no such proxy exists, then 404
    if( err ) {
      stop('The page you are looking for is not found', 404);
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
      stop('You are not authorised to access this page', 403);
      return;
    }
    // 4. now proxy
    console.log( 'Proxying request   ' + email + ':' + url + ' => ' + host );
    proxyReq(proxyServer);
  });
};

server.on('request', function(req, res) {
  
  var cookies = new Cookies(req,res,keys);
  
  var redirect = function(loc) {
    console.log('Redirecting to '+loc);
    res.writeHead(302, {'Location': loc});
    res.end();
  };
  
  var stop = function(err, code) {
    res.writeHead(code, { "Content-Type": "text/plain" });
    res.write(err);
    res.end();
  };
  
  var reqUrl = url.parse(req.url, true);
  if( !reqUrl ) {
    console.error('Failed to parse URL: '+req.url)
    stop('Bad request', 403);
    return;
  }
  
  var redirectToOauth = function() {
    redirect(oauth.authUrl(reqUrl.path));
  };
  
  var proxyReq = function(proxyServer) {
    proxyServer.web(req,res);
  };
  
  if( reqUrl.pathname == config.oauth.callbackPath ) {
    oauth.action(reqUrl.query.code, reqUrl.query.state, function( err, email, path ) {
      if( err ) {
        console.error(err);
        stop('Bad request', 403);
        return;
      }
      cookies.set(config.cookie.name, email, { signed: true, secureProxy: true, overwrite: true, maxAge: config.cookie.maxAge });
      redirect(path);
    });
    return;
  } 
  
  // normal path processing
  handleRequest(req.url, cookies, stop, redirectToOauth, proxyReq);
    
});

server.on('upgrade', function (req, socket, head) {
  var cookies = new Cookies(req,{},keys);
  
  var end = function(err) {
    console.log(err);
    socket.end();
  };
  
  var proxyReq = function(proxyServer) {
     proxyServer.ws(req, socket, head);
  };
  
  handleRequest(req.url, cookies, end, end, proxyReq);
  
});

server.listen(process.env.PORT || config.server.port || 3000, process.env.IP || "0.0.0.0", function() {
  var addr = server.address();
  console.log("Google auth proxy server listening at", addr.address + ":" + addr.port);
});
