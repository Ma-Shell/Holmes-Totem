# imports for tornado
import tornado
from tornado import web, httpserver
from tornado.options import options, parse_config_file
# imports for logging
import traceback
import os
from os import path

import logging
import os
import subprocess
import hashlib
import tempfile
import shutil

class TempAnalysisFile(object):
    """
    Temporary Analysis File class.
    """

    def __init__(self, obj):
        self.obj = obj
        print(obj)

    def __enter__(self):
        """
        Create the temporary file on disk.
        """

        tempdir = tempfile.mkdtemp()
        self.directory = tempdir
        #tfile = os.path.join(tempdir, str(self.obj.id))
        tfile = os.path.join(tempdir, "1234")
        with open(tfile, "wb") as f:
            #f.write(self.obj.filedata.read())
            f.write(open(self.obj).read())
        return tfile

    def __exit__(self, type, value, traceback):
        """
        Cleanup temporary file on disk.
        """

        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)

def UPXRun(obj):
    retdata = []
    #upx_path = config.get("upx_path", "")
    #upx_path = "upx" # options.upx_path
    upx_path = options.upx_path

    # _write_to_file() will delete this file at the end of the "with" block.
    # with TempAnalysisFile(self.current_task.obj) as tmp_file:
    with TempAnalysisFile(obj) as tmp_file:
        (working_dir, filename) = os.path.split(tmp_file)
        args = [upx_path, "-q", "-d", filename]

        # UPX does not generate a lot of output, so we should not have to
        # worry about this hanging because the buffer is full
        proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, cwd=working_dir)

        # Note that we are redirecting STDERR to STDOUT, so we can ignore
        # the second element of the tuple returned by communicate().
        output = proc.communicate()[0]
        #self._debug(output)
        print(output)

        if proc.returncode:
            # UPX return code of 1 indicates an error.
            # UPX return code of 2 indicates a warning (usually, the
            # file was not packed by UPX).
            msg = ("UPX could not unpack the file.")
            #self._warning(msg)
            print(msg)
            return

        with open(tmp_file, "rb") as newfile:
            data = newfile.read()

        #TODO: check to make sure file was modified (new MD5), indicating
        # it was actually unpacked
        md5 = hashlib.md5(data).hexdigest()
        filename = md5 + ".upx"

        #handle_file(filename, data, obj.source,
        #            related_id=str(obj.id),
        #            campaign=obj.campaign,
        #            method=self.name,
        #            relationship=RelationshipTypes.PACKED_FROM,
        #            user=self.current_task.username)

        # Filename is just the md5 of the data...
        #self._add_result("file_added", filename, {'md5': filename})
        retdata.append(filename)

    return retdata


class UPXProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            fullPath = os.path.join('/tmp/', filename)
            data = UPXRun(fullPath)
            if(data):
                print(len(data))
                self.write(data)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
Copyright 2015 Holmes Processing
        """
        self.write(description)


class UPXApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/upx/([a-zA-Z0-9\-]*)', UPXProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    tornado.options.define('upx_path', default='upx', type=str)
    tornado.options.parse_config_file("service.conf")

    server = tornado.httpserver.HTTPServer(UPXApp())
    server.listen(7725)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
