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

def test_iplookup():
    server = SocketServer.TCPServer(('', 0), http.HTTPHandler)
    server.cfg = ModuleConfig('http.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    headers = { "User-Agent": 'Google-Bot', "Host": 'ipgoat.com' }
    req = urllib2.Request("http://127.0.0.1:{0}".format(
                            server.socket.getsockname()[1]), headers=headers)
    resp = urllib2.urlopen(req).read()
    assert "11.22.33.44" in resp

def test_iplookup_raw():
    server = SocketServer.TCPServer(('', 0), http.HTTPHandler)
    server.cfg = ModuleConfig('http.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    headers = { "Host": 'checkip.dyndns.org' }
    req = urllib2.Request("http://127.0.0.1:{0}/plain".format(
                            server.socket.getsockname()[1]), headers=headers)
    resp = urllib2.urlopen(req).read()
    assert resp.startswith("11.22.33.44")
