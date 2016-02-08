# flaskdav

WebDAV server based on Flask.

## Code

### HTTPS support

flaskdav supports HTTPS when running with options <code>--cert path/to/certificate</code> and <code>--key path/to/key</code>.

To generate a private key and associated SSL certificate:

    openssl req -nodes -newkey rsa -days 365 -keyout "ssl.key" -x509 -out "ssl.cert"

### Cookie authentication

A cookie is set for every different Origin and contains a HMAC signature of the Origin and the User-Agent of the app accessing it. The cookie is set with HttpOnly flag, so that it cannot be read by JavaScript apps.

The HMAC key is reset each time you restart the server.

## Example

    python flaskdav.py --cert ssl.cert --key ssl.key --path /

tells the server to use the generated SSL key and certificate, and to give access to the full system.

## Script

On NayuOS, do:

   bash runflaskdav

to run flaskdav on / or give an absolute path as argument:

   bash runflaskdav /media/removable

## LICENSE

flaskdav is under the GPL2 license.

utils.py is a modified version of PyWebDAV's files that are under GPL2 License
original files:
*    https://code.google.com/p/pywebdav/source/browse/pywebdav/server/fshandler.py
*    https://code.google.com/p/pywebdav/source/browse/pywebdav/lib/propfind.py
*    https://code.google.com/p/pywebdav/source/browse/pywebdav/lib/utils.py

## TODO
- support LOCK/UNLOCK
- support PROPPATCH
- continue cleaning PROPFIND code
- remove Resource class
- read large data received via PUT/PROPFIND methods by chunks
