from itsdangerous import Signer, base64_encode, base64_decode
from flask import Flask, request, render_template, make_response, g, Response
from flask.views import MethodView

import urlparse
import shutil
import utils
import os
import mimetypes

app = Flask(__name__.split('.')[0])
app.config.from_object(__name__)

BUFFER_SIZE = 128000

ALLOWED_METHODS = ['GET', 'PUT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE',
                   'COPY', 'MOVE', 'OPTIONS']

def generate_key():
    """
       set application's secret key used for HMAC signature
    """
    app.secret_key = os.urandom(24)

def debug(content):
    """
       print debug info if debug mode
    """
    if app.debug:
        print(content)

URI_BEGINNING_PATH = {
    'authorization': '/login/',
    'system': '/system/',
    'webdav': '/webdav/',
    'links': '/'
}

def generate_cookie_info(origin=None):
    """
       cookie content is based on Origin header and User-Agent
       (later HMAC'ed)
    """

    if not origin:
        origin = request.headers.get('Origin')
    useragent = request.headers.get('User-Agent')
    return '%s %s' % (str(origin), str(useragent))

def verify_cookie(cookey):
    """
       verify that the signature contained in the cookie corresponds to the
       informations sent by the app (see generate_cookie_info)
    """

    is_correct = False

    debug("verify_cookie for origin: " + base64_decode(cookey))
    cookie_value = request.cookies.get(cookey)
    if cookie_value:
        debug("cookie exists for this origin")
        s = Signer(app.secret_key)
        expected_cookie_content = \
            generate_cookie_info(base64_decode(cookey))
        expected_cookie_content = s.get_signature(expected_cookie_content)
        debug("verify_cookie: " + cookie_value + ", " + expected_cookie_content)

        if expected_cookie_content == cookie_value:
            debug('correct cookie')
            is_correct = True
        else:
            debug('incorrect cookie')

    return is_correct

def is_authorized():
    """
       is the app get authorization to access the WebDAV (check cookies)
    """

    debug('is authorized, looking into cookies:\n' + str(request.cookies))
    origin = request.headers.get('Origin')
    if origin is None: # request from same origin
        return True
    return verify_cookie(base64_encode(origin))


@app.before_request
def before_request():
    """
       * put in g the prepared response with status and headers
       that can be changed by some methods later
       * allow cross origin for webdav uri that are authorized
       and filter unauthorized requests!
       * prepare response to OPTIONS request on webdav
    """
    if request.path.startswith(URI_BEGINNING_PATH['webdav']):
        response = None

        headers = {}
        headers['Access-Control-Max-Age'] = '3600'
        headers['Access-Control-Allow-Credentials'] = 'true'
        headers['Access-Control-Allow-Headers'] = \
            'Origin, Accept, Accept-Encoding, Content-Length, ' + \
            'Content-Type, Authorization, Depth, If-Modified-Since, '+ \
            'If-None-Match'
        headers['Access-Control-Expose-Headers'] = \
            'Content-Type, Last-Modified, WWW-Authenticate'
        origin = request.headers.get('Origin')
        headers['Access-Control-Allow-Origin'] = origin

        specific_header = request.headers.get('Access-Control-Request-Headers')

        if is_authorized():
            status_code = 200

        elif request.method == 'OPTIONS' and specific_header:
            # tells the world we do CORS when authorized
            debug('OPTIONS request special header: ' + specific_header)
            headers['Access-Control-Request-Headers'] = specific_header
            headers['Access-Control-Allow-Methods'] = ', '.join(ALLOWED_METHODS)
            response = make_response('', 200, headers)
            return response

        else:
            s = Signer(app.secret_key)
            headers['WWW-Authenticate'] = 'Nayookie login_url=' + \
                urlparse.urljoin(request.url_root,
                URI_BEGINNING_PATH['authorization']) + '?sig=' + \
                s.get_signature(origin) + '{&back_url,origin}'
            response = make_response('', 401, headers)
            # do not handle the request if not authorized
            return response

        g.status = status_code
        g.headers = headers

class WebDAV(MethodView):
    """ WebDAV server that handles request when destinated to it """
    methods = ALLOWED_METHODS

    def __init__(self):
        self.baseuri = URI_BEGINNING_PATH['webdav']

    def get_body(self):
        """
           get the request's body
        """

        request_data = request.data

        try:
            length = int(request.headers.get('Content-length'))
        except ValueError:
            length = 0

        if not request_data and length:
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
        status = g.status
        headers = g.headers

        localpath = app.fs_handler.uri2local(URI_BEGINNING_PATH['webdav'] + pathname)
        data = ''

        if os.path.isdir(localpath):
            data = render_template('get_collection.html', link_list=app.fs_handler.get_children(URI_BEGINNING_PATH['webdav'] + pathname))
        elif os.path.isfile(localpath):
            try:
                headers["Content-type"] = mimetypes.guess_type(localpath)[0]
                data_resource = app.fs_handler.get_data(URI_BEGINNING_PATH['webdav'] + pathname)
                if len(data_resource) > BUFFER_SIZE:
                    def generate():
                        data = data_resource.read(BUFFER_SIZE)
                        while data:
                            debug('get a chunk: ' + data)
                            yield data
                            data = data_resource.read(BUFFER_SIZE)
                    return Response(response=generate(), status=status,
                                    headers=headers)
                return Response(response=data_resource.read(BUFFER_SIZE),
                                status=status, headers=headers)
            except Exception, e:
                debug(e)
                status = 500
        else:
            status = 404

        return make_response(data, status, headers)

    def put(self, pathname):
        """
            PUT:
            on collection: 405 Method Not Allowed,
            on ressource: create if not exists, else change content
        """

        status = g.status
        headers = g.headers

        localpath = app.fs_handler.uri2local(URI_BEGINNING_PATH['webdav'] + pathname)
        # TODO: get large request chunk by chunk...
        request_body = self.get_body()
        if request_body is None:
            status = 500
        elif os.path.isdir(localpath):
            status = 405
        else:
            status = app.fs_handler.put(URI_BEGINNING_PATH['webdav'] + pathname, request_body)

        return make_response('', status, headers)

    def propfind(self, pathname):
        """
           PROPFIND:
           return informations about the properties of a resource/collection
           into a XML body response
        """
        status = g.status
        headers = g.headers

        pf = utils.PropfindProcessor(
            URI_BEGINNING_PATH['webdav'] + pathname,
            app.fs_handler,
            request.headers.get('Depth', 'infinity'),
            self.get_body())
        try:
            response = make_response(pf.create_response() + '\n', status, headers)
        except IOError:
            response = make_response('', 404, headers)

        return response

    def proppatch(self, pathname):
        """
           PROPPATCH:
           allow changes of the properties
        """

        headers = g.headers

        # currently unsupported
        status = 501

        return make_response('', status, headers)

    def mkcol(self, pathname):
        """
            MKCOL:
            creates a collection (that corresponds to a directory on the file
            system)
        """

        headers = g.headers

        status = app.fs_handler.mkcol(URI_BEGINNING_PATH['webdav'] + pathname)
        return make_response('', status, headers)

    def delete(self, pathname):
        """
           DELETE:
           delete a resource or collection
        """

        status = g.status
        headers = g.headers

        localpath = app.fs_handler.uri2local(URI_BEGINNING_PATH['webdav'] + pathname)
        if not os.path.exists(localpath):
            status = 404
        if os.path.isdir(localpath):
            try:
                shutil.rmtree(localpath)
                status = 204
            except OSError:
                status = 403
        elif os.path.isfile(localpath):
            try:
                os.remove(localpath)
                status = 204
            except OSError:
                status = 403
        return make_response('', status, headers)

    def copy(self, pathname):
        """
           COPY:
           copy a resource or collection
        """

        status = g.status
        headers = g.headers

        localpath = app.fs_handler.uri2local(URI_BEGINNING_PATH['webdav'] + pathname)
        host = request.headers['Host']
        destination = request.headers['Destination'].split(
            host + URI_BEGINNING_PATH['webdav'],
            1)[-1]
        destination_path = app.fs_handler.uri2local(destination)
        debug('COPY: %s -> %s' % (localpath, destination_path))

        if not os.path.exists(localpath):
            status = 404
        elif not destination_path:
            status = 400
        elif 'Overwrite' in request.headers and \
        request.headers['Overwrite'] == 'F' \
        and os.path.exists(destination_path):
            status = 412
        else:
            status = 201
            if os.path.exists(destination_path):
                status = self.delete(destination)

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
        return make_response('', status, headers)

    def move(self, pathname):
        """
           MOVE:
           move a resource or collection
        """

        headers = g.headers

        copy_response = self.copy(URI_BEGINNING_PATH['webdav'] + pathname)
        status = copy_response.status
        if copy_response.status == '201' or copy_response.status == '204':
            delete_response = self.delete(URI_BEGINNING_PATH['webdav'] + pathname)
            if delete_response.status != '204':
                status = '424'
        return response

    def options(self, pathname):
        """
           OPTIONS:
           used to process pre-flight request but response it supposed to be
           sent in the before_request in that case...
        """

        return make_response('', g.status, g.headers)


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
        debug(request.form.items())
        if request.form.get('reset') == 'true':
            debug('old key was: ' + app.secret_key)
            generate_key()
            debug('new key is: ' + app.secret_key)
        s = Signer(app.secret_key)
        if s.get_signature(origin) == request.args.get('sig'):
            key = base64_encode(str(origin))
            back = request.args.get('back_url')

            info = generate_cookie_info(origin=origin)
            debug('Correct origin, setting cookie with info: ' + info)
            response.set_cookie(key, value=s.get_signature(info), max_age=None,
                expires=None, path='/', domain=None, secure=True, httponly=True)
        else:
            return 'Something went wrong...'

        response.status = '301' # moved permanently
        response.headers['Location'] = '/' if not back else back

    else:
        debug(request.args)
        response = make_response(render_template('authorization_page.html',
                                 cookie_list=[ base64_decode(cookey)
                                               for cookey in
                                               request.cookies.keys()
                                               if verify_cookie(cookey) ],
                                 origin=request.args.get('origin'),
                                 back_url=request.args.get('back_url')))
    return response

@app.route(URI_BEGINNING_PATH['system'])
def system():
    """
       TODO: page with system informations
    """
    return "system info"

@app.route('/')
def link_page():
    """
       TODO: nice set of links to useful local pages
       + HOWTO use the server
    """
    link_correspondance = ([ (what, where)
                             for what, where in URI_BEGINNING_PATH.iteritems()])
    return render_template('link_page.html', link_correspondance=link_correspondance)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=\
                                     'Run a local webdav/HTTP server.')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Run flask app in debug mode (not recommended ' +
                             'for use in production).')
    parser.add_argument('-p', '--path', action='store',
                        help='Path to use as WebDAV server base')
    https = parser.add_argument_group('HTTPS',
                                      'Arguments required for HTTPS support.')
    https.add_argument('--key', type=str, action='store', default=None,
                       help='SSL/TLS private key. Required for HTTPS support.')
    https.add_argument('--cert', type=str, action='store', default=None,
                       help='SSL/TLS certificate. Required for HTTPS support.')

    args = parser.parse_args()
    app.debug = args.debug

    app.fs_path = '/tmp/' if not args.path else args.path
    app.fs_handler = utils.FilesystemHandler(app.fs_path,
                                             URI_BEGINNING_PATH['webdav'])

    context = None
    if args.key and args.cert and os.path.isfile(args.key) \
    and os.path.isfile(args.cert):
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
