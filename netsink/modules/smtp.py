# Netsink - Network Sinkhole for Isolated Malware Analysis
# Copyright (C) 2014 Steve Henderson
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

from smtpd import SMTPChannel
import socket

from netsink.listener import StreamHandler
from netsink.version import __version__

class SMTPHandler(StreamHandler, SMTPChannel):
    """Fake SMTP server.  Simply accepts any incoming mail 
    messages and drops them.
    
    Reuses python's smtpd library's SMTPChannel but overrides
    the socket interaction to conform to the StreamHandler API.
    """
    version = __version__
    
    def channel_init(self):
        """Initialises the SMTPChannel structures.
        """
        self._SMTPChannel__server = NullServer()
        self._SMTPChannel__addr = None
        self._SMTPChannel__line = []
        self._SMTPChannel__state = self.COMMAND
        self._SMTPChannel__greeting = 0
        self._SMTPChannel__mailfrom = None
        self._SMTPChannel__rcpttos = []
        self._SMTPChannel__data = ''
        self._SMTPChannel__peer = None
        self._SMTPChannel__fqdn = socket.getfqdn()
        self.close = False
        self.set_terminator('\r\n')
        # to work around the getattr calls in asyncore.dispatcher 
        self.socket = {}
    
    def config(self, config):
        self.serverstring = config.get('smtp', 'serverstring')
    
    def handle(self):
        """Feed the SMTPChannel the data from the connection.
        """
        self.channel_init()
        # send the initial connection status/response
        self.push('220 %s %s' % (self._SMTPChannel__fqdn, self.serverstring))
        # feed to the SMTP library to handle rest of protocol
        line = ""
        while not self.close:
            data = self.rfile.readline()
            if not data:
                return
            line += data
            if line.endswith(self.get_terminator()):
                self.collect_incoming_data(line[:-len(self.get_terminator())])
                self.found_terminator()
                line = ""
            
    def push(self, data):
        """Override the SMTPChannel's method to use the StreamHandler's
        supplied file handle for writing.
        """
        self.wfile.write(data + '\r\n')
    
    def close_when_done(self):
        """Overridden to break out of handle() call.
        """
        self.close = True
    
    
class NullServer:
    """A null implementation of the SMTPServer for method 
    callbacks as used by SMTPChannel.
    """
    def process_message(self, peer, mailfrom, rcpttos, data):
        # will already be logged by framework so just noop
        pass
    
    