import SocketServer
import thread
import urllib2

from netsink.config import ModuleConfig
from netsink.modules import http

def test_http():
    server = SocketServer.TCPServer(('', 0), http.HTTPHandler)
    server.cfg = ModuleConfig('http.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    resp = urllib2.urlopen("http://127.0.0.1:{0}/anything/blah.html".format(
                            server.socket.getsockname()[1])).read()
    assert "Netsink" in resp
