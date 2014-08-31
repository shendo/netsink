# Netsink - Network Sinkhole for Isolated Malware Analysis
# Copyright (C) 2013-2014 Steve Henderson
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
    client.quit()

def test_ftp_login():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login('user1', 'mysecret')
    assert 'README.txt' in client.nlst()
    client.quit()

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
    client.quit()
        
def test_ftp_upload():
    server = SocketServer.TCPServer(('', 0), ftp.FTPHandler)
    server.cfg = ModuleConfig('ftp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = ftplib.FTP()
    client.connect('127.0.0.1', server.socket.getsockname()[1])
    client.login()
    with open(get_data_file("ftproot/README.txt")) as tmp:
        client.storbinary('STOR testing.txt', tmp)
    client.quit()

