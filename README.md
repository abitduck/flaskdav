# flaskdav

WebDAV server based on Flask.

## Generate a certificate at the project's root
openssl genrsa 2048 > ssl.key
openssl req -new -x509 -nodes -sha1 -days 365 -key ssl.key > ssl.cert

## LICENSE
flaskdav is under the GPL2 license.
utils.py is a modified version of PyWebDAV's server/fshandler.py under GPL2 License
original file: https://code.google.com/p/pywebdav/source/browse/pywebdav/server/fshandler.py

## TODO
- setting up cookie for authorized access
- LOCK/UNLOCK support
- PROPFIND/PROPPATCH support
