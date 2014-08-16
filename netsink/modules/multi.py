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
import inspect
import logging
import socket
import time

from netsink.config import ModuleConfig
from netsink.listener import StreamHandler
from netsink.version import __version__

log = logging.getLogger(__name__)

class Dispatcher(StreamHandler):
    version = __version__
    handlers = []
    
    def config(self, config):
        from netsink.modules import registry
        self.min_inspect = 20 # minimum bytes needed to match with
        self.read_timeout = 10 # in seconds
        
        # set the config statically once, so we can modify reference
        # on self.server for other handlers
        if not Dispatcher.handlers:
            for x in config.get('dispatcher', 'handlers').split(","):
                try:
                    Dispatcher.handlers.append(registry[x.strip()])
                except (LookupError, ImportError):
                    log.warn("Dispatcher unable to import handler module: %s", x)
        # copy list for this instance 
        self.handlers = list(Dispatcher.handlers)
    
    def handle(self):
        data = ""
        num_timeouts = 0
        while True:
            try:
                # set a timeout in case client is waiting for server
                # to send first message...
                self.connection.settimeout(self.read_timeout)
                data = self.connection.recv(2048, socket.MSG_PEEK)
                # conn closed?
                if not len(data):
                    break
                if len(data) < self.min_inspect:
                    continue
                log.debug("Peeking at data: %s", repr(data))
                # switch back to blocking so handlers can use rfile/wfile
                self.connection.settimeout(None)
                num_timeouts = 0
                # now find right handler to consume it                
                self.dispatch(data)
                
            except socket.timeout:
                # Unable to read min data size within timeout
                # fallback to generic response/handler
                num_timeouts += 1
                # if we already tried without eliciting anything.. give up
                if num_timeouts >= 2:
                    break
                # do something more sensible here in future...
                # maybe enumerate through known protocols/C2 that
                # server side initiates conversation
                self.connection.sendall("Hello from netsink?\n")
            time.sleep(0.1)
        log.debug("Dispatcher closing socket to client %s", self.client_address)
            
    def dispatch(self, data):
        from netsink.modules import registry
        for x in self.handlers:
            if x.match(data):
                log.info("Packet data matches '%s' - dispatching", str(x))
                if inspect.isclass(x):
                    # instantiate and copy attributes
                    for name, cls in registry.items():
                        if x == cls:
                            self.server.cfg = ModuleConfig("%s.conf" % name).cfg                    
                    handler = x(self.request, self.client_address, self.server)
                    # copy back as handler may have wrapped/modified
                    # the connection.. eg. upgrading to ssl/tls
                    self.connection = handler.connection
                    self.request = handler.connection
                    # keep reference for stateful use if needed later
                    # in same conversation                    
                    self.handlers.insert(0, handler)
                else:
                    # existing instance, just copy over latest attributes
                    # in case they have changed since last used
                    x.request = self.request
                    x.connection = self.connection
                    x.client_address = self.client_address
                    x.rfile = self.rfile
                    x.wfile = self.wfile
                    x.handle()
                return
        # default for no match.. just try to consume?
        self.connection.recv(2048)
        log.warning("Could not find handler to match traffic, consuming. %s", 
                    repr(data))
            
                
        
    