import sys
import urlparse
import os
import time
from string import joinfields, split, lower
import types
import shutil

BUFFER_SIZE = 128 * 1000

class Resource(object):
    # XXX this class is ugly
    def __init__(self, fp, file_size):
        self.__fp = fp
        self.__file_size = file_size

    def __len__(self):
        return self.__file_size

    def __iter__(self):
        while 1:
            data = self.__fp.read(BUFFER_SIZE)
            if not data:
                break
            yield data
            time.sleep(0.005)
        self.__fp.close()

    def read(self, length = 0):
        if length == 0:
            length = self.__file_size

        data = self.__fp.read(length)
        return data


class FilesystemHandler():
    """
    Model a filesystem for DAV

    This class models a regular filesystem for the DAV server

    The basic URL will be http://localhost/
    And the underlying filesystem will be /tmp

    Thus http://localhost/gfx/pix will lead
    to /tmp/gfx/pix

    """

    def __init__(self, directory, uri, verbose=False):
        self.setDirectory(directory)
        self.setBaseURI(uri)
        # should we be verbose?
        self.verbose = verbose

    def setDirectory(self, path):
        """ Sets the directory """

        if not os.path.isdir(path):
            raise Exception, '%s not must be a directory!' % path

        self.directory = path

    def setBaseURI(self, uri):
        """ Sets the base uri """

        if uri:
            self.baseuri = uri
        else:
            self.baseuri = '/'

    def uri2local(self,uri):
        """ map uri in baseuri and local part """

        path=urlparse.urlparse(uri).path.strip('/')
        fileloc=path
        filename=os.path.join(self.directory,fileloc)
        filename=os.path.normpath(filename)
        print('uri2local: %s -> %s' % (uri, filename))
        return filename

    def local2uri(self,filename):
        """ map local filename to self.baseuri """

        pnum=len(split(self.directory.replace("\\","/"),"/"))
        parts=split(filename.replace("\\","/"),"/")[pnum:]
        sparts= joinfields(parts,"/")
        uri=urlparse.urljoin(self.baseuri, sparts)
        print('local2uri: %s -> %s' % (filename, uri))
        return uri

    def get_children(self, uri, filter=None):
        """ return the child objects as self.baseuris for the given URI """

        fileloc=self.uri2local(uri)
        filelist=[]

        if os.path.exists(fileloc):
            if os.path.isdir(fileloc):
                try:
                    files=os.listdir(fileloc)
                except:
                    raise 404

                for file in files:
                    newloc=os.path.join(fileloc,file)
                    filelist.append(self.local2uri(newloc))
        return filelist

    def get_data(self,uri, range = None):
        """ return the content of an object """

        path=self.uri2local(uri)
        if os.path.exists(path):
            if os.path.isfile(path):
                file_size = os.path.getsize(path)
                if range == None:
                    fp=open(path,"r")
                    return Resource(fp, file_size)
                else:
                    if range[1] == '':
                        range[1] = file_size
                    else:
                        range[1] = int(range[1])

                    if range[0] == '':
                        range[0] = file_size - range[1]
                    else:
                        range[0] = int(range[0])

                    if range[0] > file_size:
                        return 416

                    if range[1] > file_size:
                        range[1] = file_size

                    fp = open(path, "r")
                    fp.seek(range[0])
                    return Resource(fp, range[1] - range[0])
            elif os.path.isdir(path):
                # GET for collections is defined as 'return s/th meaningful' :-)
                from StringIO import StringIO
                stio = StringIO('Directory at %s' % uri)
                return Resource(StringIO('Directory at %s' % uri), stio.len)
            else:
                pass
                # also raise an error for collections
                # don't know what should happen then..

        return 404


    def put(self, uri, data, content_type=None):
        """ put the object into the filesystem """
        path=self.uri2local(uri)
        try:
            fp=open(path, "w+")
            if isinstance(data, types.GeneratorType):
                for d in data:
                    fp.write(d)
            else:
                if data:
                    fp.write(data)
            fp.close()
            status = 201
        except:
            status = 409

        return status

    def mkcol(self,uri):
        """ create a new collection """
        path=self.uri2local(uri)

        # remove trailing slash
        if path[-1]=="/": path=path[:-1]

        # test if file already exists
        if os.path.exists(path):
            return 405

        # test if parent exists
        h,t=os.path.split(path)
        if not os.path.exists(h):
            return 409

        # test, if we are allowed to create it
        try:
            os.mkdir(path)
            return 201
        # No space left
        except IOError:
            return 507
        except:
            return 403
