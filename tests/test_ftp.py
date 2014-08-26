import SocketServer
import ftplib
import thread
from netsink import get_data_file
from netsink.config import ModuleConfig
from netsink.modules import ftp

def test_ftp_anonymous():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login()
    assert 'README.txt' in client.nlst()

def test_ftp_login():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login('user1', 'mysecret')
    assert 'README.txt' in client.nlst()

def test_ftp_download():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login()
    def check_content(content):
        assert 'Nothing to see here' in content
    client.retrbinary('RETR README.txt', check_content)
        
def test_ftp_upload():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login()
    with open(get_data_file("ftproot/README.txt")) as tmp:
        client.storbinary('STOR testing.txt', tmp)
