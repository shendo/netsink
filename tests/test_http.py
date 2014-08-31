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
