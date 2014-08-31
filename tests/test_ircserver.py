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

import irc.client

from netsink.config import ModuleConfig
from netsink.modules import ircserver

def test_irc():
    server = SocketServer.TCPServer(('', 0), ircserver.IRCHandler)
    server.cfg = ModuleConfig('irc.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = irc.client.IRC()
    conn = client.server().connect('127.0.0.1', server.socket.getsockname()[1], 'nickname')
    conn.join("#testchan", key="12345")
    conn.privmsg("#testchan", "ready for tasking")
    # drain response messages
    for _ in range(6):
        client.process_once(0.015)
    conn.close()
