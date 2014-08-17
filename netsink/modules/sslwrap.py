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
import re
import socket
import ssl

from netsink import get_data_file
from netsink.listener import StreamHandler
from netsink.version import __version__

class SSLHandler(StreamHandler):
    """Stream Handler that 'upgrades' a TCP connection to TLS/SSL transport.
    """
    version = __version__
    
    @staticmethod
    def match(data):
        return re.match(b'\x16\x03[\x00-\x03]..\x01', data)
    
    def config(self, config):
        self.certfile = config.get('ssl', 'certfile')
        self.keyfile = config.get('ssl', 'keyfile')
        
    def handle(self):
        """Attempts SSL/TLS handshake on current connection
        and replaces the it with a wrapped socket to handle
        if successful.
        """
        self.connection = PeekableSSLSocket(self.connection,  
                                        keyfile=get_data_file(self.keyfile), 
                                        certfile=get_data_file(self.certfile), 
                                        server_side=True)

class PeekableSSLSocket(ssl.SSLSocket):
    """Extension to SSLSocket that adds support for 
    socket.MSG_PEEK flag in ssl wrapped recv() calls.
    Most definitely not thread-safe.
    """
    
    def __init__(self, sock, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=ssl.CERT_NONE,
                 ssl_version=ssl.PROTOCOL_SSLv23, ca_certs=None,
                 do_handshake_on_connect=True,
                 suppress_ragged_eofs=True, ciphers=None):
        
        ssl.SSLSocket.__init__(self, sock, keyfile, certfile, 
                               server_side, cert_reqs, ssl_version, 
                               ca_certs, do_handshake_on_connect, 
                               suppress_ragged_eofs)
        self.peekbuff = ''
        
    def read(self, size=1024, peek=False):
        """Read up to SIZE bytes and return them.
        Return zero-length string on EOF."""
        try:
            if peek:
                self.peekbuff += self._sslobj.read(size)
                return self.peekbuff
            if self.peekbuff:
                tmp = self.peekbuff
                self.peekbuff = ''
                return tmp
            return self._sslobj.read(size)
        except ssl.SSLError, x:
            if x.args[0] == ssl.SSL_ERROR_EOF and self.suppress_ragged_eofs:
                return ''
            else:
                raise
            
    def recv(self, buflen=1024, flags=0):
        if self._sslobj:
            if flags != 0 and flags != socket.MSG_PEEK:
                raise ValueError(
                    "Only MSG_PEEK flag allowed in calls to recv() on %s" %
                    self.__class__)
            return self.read(buflen, flags == socket.MSG_PEEK)
        else:
            return self._sock.recv(buflen, flags)