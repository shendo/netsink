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

import logging
import SocketServer
import ssl

from netsink import get_data_file
from netsink.config import Config, ModuleConfig

log = logging.getLogger(__name__)

class Listener(object):
    """A listener for a given port and protocol handler.
    Corresponding socket server instance can be retrieved as self.server
    """
    def __init__(self, name, port, handler, socktype, config):
        self.name = name
        self.port = port
        self.socktype = socktype
        self.server = None
        
        globalconf = Config()
        if socktype.upper() == 'UDP':
            self.server = SocketServer.ThreadingUDPServer(('', port), handler)
        elif socktype.upper() == 'TCP':
            self.server = SocketServer.ThreadingTCPServer(('', port), handler)
        elif socktype.upper() == 'SSL':
            if not get_data_file(globalconf.certfile) or not get_data_file(globalconf.keyfile):
                log.warn("Cannot find certfile: %s or keyfile: %s for ssl", 
                         globalconf.certfile, globalconf.keyfile)
            else:
                self.server = SocketServer.ThreadingTCPServer(('', port), handler)
                self.server.socket = ssl.wrap_socket(self.server.socket, 
                                                keyfile=get_data_file(globalconf.keyfile), 
                                                certfile=get_data_file(globalconf.certfile), 
                                                server_side=True)
        else:
            log.warn("Unsupported or invalid socket type: %s for config '%s'", 
                     socktype, name)

        if self.server:
            self.server.cfg = ModuleConfig(config).cfg
        
class IOWrapper(object):
    """Intercepts read/write calls to handler to perform logging or other actions.
    """
    def __init__(self, client, server, rfile, wfile, fastflush=False):
        self.client = client
        self.server = server
        self.rfile = rfile
        self.wfile = wfile
        self.rbuff = ""
        self.wbuff = ""
        # by default will delay logging to aggregate multiple calls
        self.fastflush = fastflush
        
    def read(self, size=-1):
        """Wrap read() calls.
        """
        self.logwrite()
        data = self.rfile.read(size)
        self.rbuff += data
        if self.fastflush:
            self.logread()
        return data
    
    def readline(self):
        """Wrap readline() calls.
        """
        self.logwrite()
        data = self.rfile.readline()
        self.rbuff += data
        if self.fastflush:
            self.logread()
        return data
    
    def write(self, data):
        """Wrap write() calls.
        """
        self.logread()
        self.wbuff += data
        if self.fastflush:
            self.logwrite()
        return self.wfile.write(data)
    
    def logread(self):
        """Flush the currently read bytes to the log.
        """
        if self.rbuff:
            log.info("Read from client %s to %s:\n%s", 
                         str(self.client), str(self.server), self._escape(self.rbuff))
        self.rbuff = ""
    
    def logwrite(self):
        """Flush the currently written bytes to the log"""
        if self.wbuff:
            log.info("Written to client %s from %s:\n%s", 
                         str(self.client), str(self.server), self._escape(self.wbuff))
        self.wbuff = ""
    
    @staticmethod
    def _escape(s):
        """Prepares a string for printing to the log.
        This involves escaping any non-printable chars but preserving newlines.
        """
        return repr(s).replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")[1:-1]
    
class UDPHandler(SocketServer.DatagramRequestHandler):
    """UDP base handler class
    """
    def setup(self):
        """Called when a new datagram arrives.
        Wraps the I/O objects for logging.
        """
        SocketServer.DatagramRequestHandler.setup(self)
        # Datagram based so flush on each send/recv
        iowrap = IOWrapper(self.client_address, 
                           self.server.server_address, 
                           self.rfile, 
                           self.wfile, 
                           fastflush=True)
        self.rfile = iowrap
        self.wfile = iowrap
        self.config(self.server.cfg)
            
    def finish(self):
        """Called after the requests has been handled to finalise any resources.
        """
        iowrap = self.rfile
        iowrap.logread()
        iowrap.logwrite()
        self.rfile = iowrap.rfile
        self.wfile = iowrap.wfile
        SocketServer.DatagramRequestHandler.finish(self)
    
class StreamHandler(SocketServer.StreamRequestHandler):
    """TCP/SSL base handler class
    """
    def setup(self):
        """Called when a new connection is established.
        Wraps the I/O objects for logging.
        """
        SocketServer.StreamRequestHandler.setup(self)
        iowrap = IOWrapper(self.client_address, 
                           self.server.server_address, 
                           self.rfile, 
                           self.wfile)
        self.rfile = iowrap
        self.wfile = iowrap
        self.config(self.server.cfg)
            
    def finish(self):
        """Called after the connection has closed to finalise any resources.
        """
        iowrap = self.rfile
        iowrap.logread()
        iowrap.logwrite()
        self.rfile = iowrap.rfile
        self.wfile = iowrap.wfile
        SocketServer.StreamRequestHandler.finish(self)
        
    @staticmethod
    def match(pkt):
        return False
