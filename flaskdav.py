from itsdangerous import Signer, base64_encode, base64_decode
from flask import Flask, request, render_template, make_response, g
from flask.views import MethodView

import urlparse
import shutil
import utils
import os

app = Flask(__name__.split('.')[0])
app.config.from_object(__name__)

FS_PATH = '/tmp/couscous'

ALLOWED_METHODS = ['GET', 'PUT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE',
                   'COPY', 'MOVE', 'OPTIONS']

def generate_key():
    """
       set application's secret key used for HMAC signature
    """
    app.secret_key = os.urandom(24)

def debug(content):
    if app.debug: print(content)

URI_BEGINNING_PATH = {
    'authorization': '/login/',
    'system': '/system/',
    'webdav': '/webdav/',
    'links': '/',
    'home': '/webdav/home/',
    'devices': '/webdav/devices/'
}

def make_cookie_content_to_be_signed(origin=None):
    """ cookie content is based on Origin header and User-Agent
    (later HMAC'ed) """

    if not origin:
        origin = request.headers.get('Origin')
    useragent = request.headers.get('User-Agent')
    return str(origin) + str(useragent)

def verify_cookie(cookey):
    """ verify that the signature contained in the cookie
    corresponds to the informations sent by the app (see
    make_cookie_content_to_be_signed) """

    is_correct = False

    debug("verify_cookie for origin: " + base64_decode(cookey))
    cookie_value = request.cookies.get(cookey)
    if cookie_value:
        debug("cookie exists for this origin")
        s = Signer(app.secret_key)
        expected_cookie_content = make_cookie_content_to_be_signed(base64_decode(cookey))
        expected_cookie_content = s.get_signature(expected_cookie_content)
        debug("verify_cookie: " + cookie_value + ", " + expected_cookie_content)

        if expected_cookie_content == cookie_value:
            debug('correct cookie')
            is_correct = True
        else:
            debug('incorrect cookie')

    return is_correct

def is_authorized(cookies_list):
    debug('is authorized, looking into cookies:\n' + str(request.cookies))
    origin = request.headers.get('Origin')
    if origin is None: # request from same origin
        return True
    return verify_cookie(base64_encode(origin))

FS_HANDLER = utils.FilesystemHandler(FS_PATH, URI_BEGINNING_PATH['webdav'])

@app.before_request
def before_request():
    """
       allow cross origin for webdav uri that are authorized
       and filter unauthorized requests!
    """
    if request.path.startswith(URI_BEGINNING_PATH['webdav']):
        response = None

        headers = {}
        headers['Access-Control-Max-Age'] = '3600'
        headers['Access-Control-Allow-Credentials'] = 'true'
        content = ''
        headers['Access-Control-Allow-Headers'] = \
            'Origin, Accept, Accept-Encoding, Content-Length, Content-Type, ' + \
            'Authorization, Depth, If-Modified-Since, If-None-Match'
        headers['Access-Control-Expose-Headers'] = \
            'Content-Type, Last-Modified, WWW-Authenticate'
        origin = request.headers.get('Origin')
        headers['Access-Control-Allow-Origin'] = origin

        specific_header = request.headers.get('Access-Control-Request-Headers')

        if is_authorized(request.cookies):
            response = make_response(content, 200)
            response.headers = headers

        elif request.method == 'OPTIONS' and specific_header:
            # tells the world we do CORS when authorized
            debug('OPTIONS request special header: ' + specific_header)
            headers['Access-Control-Request-Headers'] = specific_header
            headers['Access-Control-Allow-Origin'] = origin
            headers['Access-Control-Allow-Methods'] = ', '.join(ALLOWED_METHODS)
            response = make_response(content, 200)
            response.headers = headers
            return response

        else:
            s = Signer(app.secret_key)
            headers['WWW-Authenticate'] = 'Nayookie login_url=' + \
                urlparse.urljoin(request.url_root,
                URI_BEGINNING_PATH['authorization']) + '?sig=' + \
                s.get_signature(origin) + '{&back_url,origin}'
            response = make_response(content, 401)
            response.headers = headers
            # do not handle the request if not authorized
            return response

        g.response = response

class WebDAV(MethodView):
    methods = ALLOWED_METHODS

    def __init__(self):
        self.baseuri = URI_BEGINNING_PATH['webdav']

    def get_body(self):
        """ get the request's body """
        request_data = request.data
        if not request_data and int(request.headers['Content-length']):
            try:
                request_data = request.form.items()[0][0]
            except IndexError:
                request_data = None
        return request_data

    def get(self, pathname):
        """
           GET:
           return headers + body (resource content or list of resources)
        """
        response = g.response
        localpath = FS_HANDLER.uri2local(pathname)
        # TODO if into a collection => list of the ressources
        data = ''

        if os.path.isdir(localpath):
            data = "\n".join(FS_HANDLER.get_children(pathname))
        elif os.path.isfile(localpath):
            try:
                data_resource = FS_HANDLER.get_data(pathname)
                # TODO send large response by chunks would be nice for big
                # files... http://flask.pocoo.org/docs/0.10/patterns/streaming/
                data = data_resource.read()
            except Exception:
                response.status = '500'
        else:
            response.status = '404'

        response.data = data

        return response

    def put(self, pathname):
        """
            PUT:
            on collection: 405 Method Not Allowed,
            on ressource: create if not existschange content
        """

        response = g.response

        localpath = FS_HANDLER.uri2local(pathname)
        # TODO: get large request chunk by chunk...
        request_body = self.get_body()
        if request_body is None:
            response.status = '500'
        elif os.path.isdir(localpath):
            response.status = '405'
        else:
            response.status = str(FS_HANDLER.put(pathname, request_body))

        return response

    def propfind(self, pathname):

        response = g.response

        # currently unsupported
        response.status = '423'
        return response

    def proppatch(self, pathname):

        response = g.response

        # currently unsupported
        response.status = '423'
        return response

    def mkcol(self, pathname):
        """
            MKCOL:
            creates a collection (that corresponds to a directory on the file
            system)
        """

        response = g.response

        response.status = str(FS_HANDLER.mkcol(pathname))
        return response

    def delete(self, pathname):
        """
           DELETE:
           delete a resource or collection
        """

        response = g.response

        localpath = FS_HANDLER.uri2local(pathname)
        if not os.path.exists(localpath):
            response.status = '404'
        if os.path.isdir(localpath):
            try:
                shutil.rmtree(localpath)
                response.status = '204'
            except OSError:
                response.status = '403'
        elif os.path.isfile(localpath):
            try:
                os.remove(localpath)
                response.status = '204'
            except OSError:
                response.status = '403'
        return response

    def copy(self, pathname):
        """
           COPY:
           copy a resource or collection
        """

        response = g.response

        localpath = FS_HANDLER.uri2local(pathname)
        destination = request.headers['Destination']
        host = request.headers['Host']
        destination = destination.split(host + URI_BEGINNING_PATH['webdav'], 1)[-1]
        destination_path = FS_HANDLER.uri2local(destination)
        debug('COPY: %s -> %s' % (localpath, destination_path))

        if not os.path.exists(localpath):
            response.status = '404'
        elif not destination_path:
            response.status = '400'
        elif 'Overwrite' in request.headers and request.headers['Overwrite'] == 'F' \
        and os.path.exists(destination_path):
            response.status = '412'
        else:
            response.status = '201'
            if os.path.exists(destination_path):
                delete_response = self.delete(destination)
                response.status = '204'

            if os.path.isfile(localpath):
                try:
                    shutil.copy2(localpath, destination_path)
                except Exception:
                    debug('problem with copy2')
            else:
                try:
                    shutil.copytree(localpath, destination_path)
                except Exception:
                    debug('problem with copytree')
        return response

    def move(self, pathname):
        """
           MOVE:
           move a resource or collection
        """

        response = g.response

        copy_response = self.copy(pathname)
        response.status = copy_response.status
        if copy_response.status == '201' or copy_response.status == '204':
            delete_response = self.delete(pathname)
            if delete_response.status != '204':
                response.status = '424'
        return response

    def options(self, pathname):
        """
           OPTIONS:
           used to process pre-flight request
        """

        return g.response


app.add_url_rule(URI_BEGINNING_PATH['webdav'] + '<path:pathname>',
                 view_func=WebDAV.as_view('dav'))


@app.route(URI_BEGINNING_PATH['authorization'], methods=['GET', 'POST'])
def authorize():
    """ authorization page
        GET: returns page where the user can authorize an app to access the
             filesystem via the webdav server
        POST: set a cookie
    """

    origin = request.args.get('origin')

    if request.method == 'POST':
        response = make_response()
        if request.form.get('reset') == 'true':
            debug('old key was: ' + app.secret_key)
            generate_key()
            debug('new key is: ' + app.secret_key)
        s = Signer(app.secret_key)
        if s.get_signature(origin) == request.args.get('sig'):
            key = base64_encode(str(origin))
            back = request.args.get('back_url')
            sig = request.args.get('sig')

            debug('Correct origin, setting cookie with info: ' + make_cookie_content_to_be_signed(origin=origin))
            response.set_cookie(key, value=s.get_signature(make_cookie_content_to_be_signed(origin=origin)),
                                max_age=None, expires=None, path='/', domain=None, secure=True, httponly=True)
        else:
            return 'Something went wrong...'

        if back:
            response.status = '301' # moved permanently
            response.headers['Location'] = back
        # what if not? use referer? send bad request error? just do nothing?

    else:
        debug(request.args)
        headers = request.headers
        response = make_response(render_template('authorization_page.html',
                                 origin=request.args.get('origin'),
                                 back_url=request.args.get('back_url')))
    return response

@app.route(URI_BEGINNING_PATH['system'])
def system():
    return 'TODO: page with system informations'

@app.route('/')
def links():
    the_links = '<div><ul>'
    the_links += '\n'.join(['<li>%s: %s </li>' % (key, URI_BEGINNING_PATH[key])
                                                  for key in URI_BEGINNING_PATH.keys()])
    the_links += '</ul></div>'
    return 'TODO: nice set of links to useful local pages: %s <br> + HOWTO' % the_links

if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser(description='Run a local webdav/HTTP server.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Run flask app in debug mode (not recommended for use in production).')
    https = parser.add_argument_group('HTTPS', 'Arguments required for HTTPS support.')
    https.add_argument('--key', type=str, action='store', default=None,
                       help='SSL/TLS private key. Required for HTTPS support.')
    https.add_argument('--cert', type=str, action='store', default=None,
                       help='SSL/TLS certificate. Required for HTTPS support.')

    args = parser.parse_args()
    app.debug = args.debug

    context = None
    if args.key and args.cert and os.path.isfile(args.key) and os.path.isfile(args.cert):
        from OpenSSL import SSL
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        # TODO set strong ciphers with context.set_cipher_list()
        context.use_privatekey_file('ssl.key')
        context.use_certificate_file('ssl.cert')

    if app.debug:
        app.secret_key = 'maybe you should change me...'
    else:
        generate_key()
    app.run(host="localhost", ssl_context=context)
