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

import socket
import SocketServer
import thread
import urllib2

from netsink.config import ModuleConfig
from netsink.modules import multi

def test_dispatched_http():
    server = SocketServer.TCPServer(('', 0), multi.Dispatcher)
    server.cfg = ModuleConfig('dispatcher.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    resp = urllib2.urlopen("http://127.0.0.1:{0}/anything/blah.html".format(
                            server.socket.getsockname()[1])).read()
    assert "Netsink" in resp

def test_dispatched_https():
    server = SocketServer.TCPServer(('', 0), multi.Dispatcher)
    server.cfg = ModuleConfig('dispatcher.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    resp = urllib2.urlopen("https://127.0.0.1:{0}/anything/blah.html".format(
                            server.socket.getsockname()[1])).read()
    assert "Netsink" in resp

def test_no_match():
    server = SocketServer.TCPServer(('', 0), multi.Dispatcher)
    server.cfg = ModuleConfig('dispatcher.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', server.socket.getsockname()[1]))
    # server should just consume unknown client traffic
    s.send('asdhakdfhkajfafdhjagsdfjjhsadfhjagsd1234234123412342134asddf' * 10)
    s.close()

def test_server_initiated():
    server = SocketServer.TCPServer(('', 0), multi.Dispatcher)
    server.cfg = ModuleConfig('dispatcher.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', server.socket.getsockname()[1]))
    # client is expecting server to initiate comms
    # check that server eventually gives up and sends
    # something back in an attempt to elicit something from client
    resp = s.recv(2048)
    assert 'netsink' in resp
    s.close()

def test_small_data():
    server = SocketServer.TCPServer(('', 0), multi.Dispatcher)
    server.cfg = ModuleConfig('dispatcher.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', server.socket.getsockname()[1]))
    # multiple sends but still less than needed for pattern matching
    s.send('asdfk')
    s.send('sasd')
    s.send('00')
    # check that server eventually gives up on the small data and sends
    # something back in an attempt to elicit more comms
    resp = s.recv(2048)
    assert 'netsink' in resp
    s.close()
