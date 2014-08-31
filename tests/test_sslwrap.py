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
                   
    
    