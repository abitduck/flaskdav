import unittest
import flaskdav
import utils
import tempfile
import shutil

class FlaskdavTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        '''
           create temporary dir and files, and flaskdav test instance
        '''
        self.app = flaskdav.app

        self.app.fs_path = tempfile.mkdtemp()
        f = open(self.app.fs_path + '/file.txt', 'w')
        f.write('pouet')
        f.close()
        f = open(self.app.fs_path + '/file.js', 'w')
        f.close()
        f = open(self.app.fs_path + '/file.png', 'w')
        f.close()

        self.app.fs_handler = utils.FilesystemHandler(self.app.fs_path, '/webdav/')
        self.server = self.app.test_client()

    '''
        GET method 
    '''
    # status code
    def test_get_root_return_code_200(self):
        response = self.server.get('/')
        self.assertEqual(response.status_code, 200)

    def test_get_webdav_root_return_code_200(self):
        response = self.server.get('/webdav/')
        self.assertEqual(response.status_code, 200)

    # MIME type
    def test_plaintext_content_type(self):
        response = self.server.get('/webdav/file.txt')
        self.assertEqual(response.mimetype, 'text/plain')

    def test_plaintext_content_type(self):
        response = self.server.get('/webdav/file.js')
        self.assertEqual(response.mimetype, 'application/x-javascript')

    def test_png_content_type(self):
        response = self.app.test_client().get('/webdav/file.png')
        self.assertEqual(response.mimetype, 'image/png')

    # response body
    def test_response_body(self):
        f = open(self.app.fs_path + '/file.txt', 'w')
        f.write('pouet')
        f.close()
        response = self.server.get('/webdav/file.txt')
        self.assertEqual(response.data, 'pouet')

    '''
        PUT method 
    '''
    # status code
    def test_put_root_return_code_405(self):
        response = self.server.put('/')
        self.assertEqual(response.status_code, 405)

    def test_put_webdav_return_code_201(self):
        response = self.server.put('/webdav/put.txt', '')
        self.assertEqual(response.status_code, 201)

    # file content modification
    def test_put_webdav_content_changed(self):
        response = self.server.put('/webdav/put.txt', data='couscous')
        f = open(self.app.fs_path + '/put.txt', 'r')
        content = f.read()
        f.close()
        self.assertEqual(content, 'couscous')

    @classmethod
    def tearDownClass(self):
        '''
            cleaning temporary dir
        '''
        shutil.rmtree(self.app.fs_path)


if __name__ == '__main__':
    unittest.main()
