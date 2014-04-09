# Netsink - Network Sinkhole for Isolated Malware Analysis
# Copyright (C) 2013 Steve Henderson
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
import logging
import socket

import irc.server as irclib

irclib.log = logging.getLogger(__name__) # use our own log namespace

class IRCHandler(irclib.IRCClient):
    """Basic IRC Server support using Jason Coombs' irc python library.
    Should at least capture initial client connection and any channel joining, 
    nick setting, etc.
    """
    @staticmethod
    def match(self):
        return False
    
    def setup(self):
        """Setup the newly created client connection ready for handler.
        """
        irclib.SRV_WELCOME = self.server.cfg.get('irc', 'serverstring')
        irclib.handle_mode = self.handle_mode # ignore mode commands
        # first server connection, initialise state.. not thread-safe
        if not hasattr(self.server, "servername"):
            self.server.servername = socket.gethostname()
            self.server.channels = {}
            self.server.clients = {}
        
    
    def handle_mode(self, params):
        """No-op implementation of MODE handling.
        Really just here to avoid sending lots of 'Unknown command' 
        responses back to client as most clients will set nick and channel
        modes automatically.
        """
        pass
        