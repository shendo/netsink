import socket
import SocketServer
import ssl
import thread

from netsink.config import ModuleConfig
from netsink.modules import sslwrap

def test_sslhandler():
    server = SocketServer.TCPServer(('', 0), sslwrap.SSLHandler)
    server.cfg = ModuleConfig('ssl.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    client.connect(('127.0.0.1', server.socket.getsockname()[1]))
    assert client.ssl_version >= 2
                   
    
    