#!/usr/bin/env python

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
import threading
import time

from netsink.config import Config
from netsink.listener import Listener
from netsink.modules import registry

log = logging.getLogger("netsink")

def initlogging():
    """Initialise the logging format and handler.
    """
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    log.addHandler(handler)
    
def startlisteners(config):
    """Start all the listeners defined in the supplied config and block indefintely.
    """
    for x in config.listeners.values():
        if not registry.get(x.module):
            log.warn("Netsink module '%s' not found for config item '%s'... skipping", 
                         x.module, x.name)
            continue
        x.servers = []
        for p in x.ports:
            server = Listener(x.name, p, registry[x.module], x.socktype, x.config).server
            if server:
                x.servers.append(server)
                server_thread = threading.Thread(target=server.serve_forever)
                server_thread.setDaemon(True)
                server_thread.start()
            else:
                x.ports.pop(p)
        if x.ports:
            log.info("Listener '%s' awaiting %s activity on port/s %s", 
                         x.name, x.socktype, str(x.ports))

def wait():
    """Block indefinitely.
    """
    log.info("Waiting...")
    while True:
        time.sleep(1)
            
if __name__ == '__main__':
    initlogging()
    log.setLevel(logging.DEBUG)
    startlisteners(Config())
    wait()
    