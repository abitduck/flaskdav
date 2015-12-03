# flaskdav

WebDAV server based on Flask.

## Code

### HTTPS support

flaskdav supports HTTPS when running with options <code>--cert path/to/certificate</code> and <code>--key path/to/key</code>.

To generate a private key and associated SSL certificate:
<pre><code>openssl req -nodes -newkey rsa -days 365 -keyout "ssl.key" -x509 -out "ssl.cert"</code></pre>

### Cookie authentication

A cookie is set for every different Origin and contains a HMAC signature of the Origin and the User-Agent of the app accessing it. The cookie is set with HttpOnly flag, so that it cannot be read by JavaScript apps.

The HMAC key is reset each time you restart the server.

## LICENSE

flaskdav is under the GPL2 license.

utils.py is a modified version of PyWebDAV's server/fshandler.py under GPL2 License
original file: https://code.google.com/p/pywebdav/source/browse/pywebdav/server/fshandler.py

## TODO
- LOCK/UNLOCK support
- PROPFIND/PROPPATCH support
