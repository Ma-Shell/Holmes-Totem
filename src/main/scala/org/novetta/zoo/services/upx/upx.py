# imports for tornado
import tornado
from tornado import web, httpserver

# imports for logging
import traceback
import os
from os import path

import logging
import os
import subprocess
import hashlib



def UPXRun(obj):
    data = {}
    upx_path = config.get("upx_path", "")

        # _write_to_file() will delete this file at the end of the "with" block.
        with self._write_to_file() as tmp_file:
            (working_dir, filename) = os.path.split(tmp_file)
            args = [upx_path, "-q", "-d", filename]

            # UPX does not generate a lot of output, so we should not have to
            # worry about this hanging because the buffer is full
            proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, cwd=working_dir)

            # Note that we are redirecting STDERR to STDOUT, so we can ignore
            # the second element of the tuple returned by communicate().
            output = proc.communicate()[0]
            self._debug(output)

            if proc.returncode:
                # UPX return code of 1 indicates an error.
                # UPX return code of 2 indicates a warning (usually, the
                # file was not packed by UPX).
                msg = ("UPX could not unpack the file.")
                self._warning(msg)
                return

            with open(tmp_file, "rb") as newfile:
                data = newfile.read()

            #TODO: check to make sure file was modified (new MD5), indicating
            # it was actually unpacked
            md5 = hashlib.md5(data).hexdigest()
            filename = md5 + ".upx"
            handle_file(filename, data, obj.source,
                        related_id=str(obj.id),
                        campaign=obj.campaign,
                        method=self.name,
                        relationship=RelationshipTypes.PACKED_FROM,
                        user=self.current_task.username)
            # Filename is just the md5 of the data...
            self._add_result("file_added", filename, {'md5': filename})

    return data


class UPXProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            fullPath = os.path.join('/tmp/', filename)
            data = UPXRun(fullPath)
            print len(data)
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
    server = tornado.httpserver.HTTPServer(UPXApp())
    server.listen(7725)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
