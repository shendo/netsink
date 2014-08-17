import socket
import SocketServer
import thread

from dnslib import DNSRecord, DNSQuestion

from netsink.config import ModuleConfig
from netsink.modules import dns

def test_dns():
    server = SocketServer.UDPServer(('', 0), dns.DNSHandler)
    server.cfg = ModuleConfig('dns.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    resp = DNSRecord(q=DNSQuestion("google.com")).send(
                     "127.0.0.1", port=server.socket.getsockname()[1])
    assert str(resp.get_a().rdata) == socket.gethostbyname(socket.gethostname())
