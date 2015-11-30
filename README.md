# flaskdav

WebDAV server based on Flask.

## Generate a certificate at the project's root
openssl req -nodes -newkey rsa -days 365 -keyout "ssl.key" -x509 -out "ssl.cert"

## LICENSE
flaskdav is under the GPL2 license.
utils.py is a modified version of PyWebDAV's server/fshandler.py under GPL2 License
original file: https://code.google.com/p/pywebdav/source/browse/pywebdav/server/fshandler.py

## TODO
- setting up cookie for authorized access
- LOCK/UNLOCK support
- PROPFIND/PROPPATCH support
