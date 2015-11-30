from flask import Flask, request, redirect, url_for, render_template, make_response, g
from flask.views import MethodView
import shutil
import utils
import os
DEBUG = True


app = Flask(__name__.split('.')[0])
app.config.from_object(__name__)

FS_PATH = '/tmp/couscous'
SECRET_KEY = os.urandom(24)

URI_BEGINNING_PATH = {
    'authorization': '/login/',
    'system': '/system/',
    'webdav': '/webdav/',
    'links': '/',
    'home': '/webdav/home/',
    'editor': '/editor',
    'devices': '/webdav/devices/'
}

def verify_cookie(cookie):
    return False

def is_authorized(cookies_list):
    #return any(verify_cookie(cookie) for cookie in cookies_list)
    return True

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
        if is_authorized(request.cookies):
            headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
            headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Accept-Encoding, Content-Length, Content-Type, Authorization, Depth, If-Modified-Since, If-None-Match'
            headers['Access-Control-Expose-Headers'] = 'Content-Type, Last-Modified, WWW-Authenticate'
            response = make_response(content, 200)
            response.headers = headers
        else:
            headers['WWW-Authenticate'] = 'Nayookie login_url=' + request.url_root + URI_BEGINNING_PATH['authorization'] + '{?back_url}'
            response = make_response(content, 401)
            response.headers = headers
            # do not handle the request if not authorized
            return response

        g.response = response

class WebDAV(MethodView):
    methods = ['GET', 'PUT', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'DELETE', 'COPY', 'MOVE']

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
                # 403?
                response.status = '403'
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
            creates a collection (that corresponds to a directory on the file system)
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
        print('COPY: %s -> %s' % (localpath, destination_path))

        if not os.path.exists(localpath):
            response.status = '404'
        elif not destination_path:
            response.status = '400'
        elif 'Overwrite' in request.headers and request.headers['Overwrite'] == 'F' and os.path.exists(destination_path):
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
                    print('problem with copy2')
            else:
                try:
                    shutil.copytree(localpath, destination_path)
                except Exception:
                    print('problem with copytree')
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

app.add_url_rule(URI_BEGINNING_PATH['webdav'] + '<path:pathname>', view_func=WebDAV.as_view('dav'))


@app.route(URI_BEGINNING_PATH['authorization'], methods=['GET', 'POST'])
def authorize():
    origin = request.headers.get('Origin')

    if request.method == 'POST':
        response = make_response(render_template('authorization_page_cookie_set.html', headers=headers, origin=origin, back_url=back_url))
        response.set_cookie('mycookie', value='', max_age=None, expires=None, path='/',
                            domain=None, secure=None, httponly=False)
    else:
        headers = request.headers
        back_url = request.args.get('back_url')
        response = make_response(render_template('authorization_page.html', headers=headers, origin=origin, back_url=back_url))
    return response

@app.route(URI_BEGINNING_PATH['editor'])
def editor():
    return render_template('code_editor.html')

@app.route(URI_BEGINNING_PATH['system'])
def system():
    return 'TODO: page with system informations'

@app.route('/')
def links():
    the_links = '<div><ul>'
    the_links += '\n'.join(['<li>%s: %s </li>' % (key, URI_BEGINNING_PATH[key]) for key in URI_BEGINNING_PATH.keys()])
    the_links += '</ul></div>'
    return 'TODO: nice set of links to useful local pages: %s <br> + HOWTO' % the_links

if __name__ == '__main__':
    from OpenSSL import SSL
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    # TODO set strong ciphers with context.set_cipher_list()
    # TODO give path to key/cert using command line parameters
    context.use_privatekey_file('ssl.key')
    context.use_certificate_file('ssl.cert')

    app.run(ssl_context=context)
