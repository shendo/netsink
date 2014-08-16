#!/usr/bin/env python

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
import socket
import sys
import threading
import time

from netsink.config import Config, ModuleConfig
from netsink.listener import Listener
from netsink.modules import registry
from netsink.redirection import Redirector

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
            try:
                server = Listener(x.name, p, registry[x.module], x.socktype, x.config).server
                x.servers.append(server)
                server_thread = threading.Thread(target=server.serve_forever)
                server_thread.setDaemon(True)
                server_thread.start()
            except socket.error:
                log.warning("Unable to establish listener on port %s... skipping.", p)
                x.ports.remove(p)
        if x.ports:
            log.info("Listener '%s' awaiting %s activity on port/s %s", 
                         x.name, x.socktype, str(x.ports))
    return config.listeners.values()

def redirection(config, listeners):
    """Setup port forwarding and redirection for the given listeners/config.
    """
    if not Redirector.available():
        log.warn("Connection redirection enabled but not available. "
                     "Ensure 'iptables' is installed and current user has sufficient privileges.")
        return
    
    if Redirector.existing_rules():
        log.warn("Existing rules found in iptables. Not enabling connection redirection in case of conflict.")
        return
    
    redir = Redirector()
    # pass through all listener ports
    for listener in [ x for x in listeners if x.socktype in ['SSL', 'TCP'] ]:
        redir.add_forwarding("tcp", listener.ports)
    # pass through any explicitly excluded ports
    exclusions = config.cfg.get("redirection", "port_exclusions")
    if exclusions:
        redir.add_forwarding("tcp", exclusions.split(","))
    # forward all other ports to generic listener
    generic = config.cfg.get("redirection", "port_forwarding")
    if generic:
        redir.add_forwarding("tcp", outport=generic)
    # forward all protocols to local address
    redir.add_forwarding()
    
def wait():
    """Block indefinitely until Ctrl-C.
    """
    log.info("Waiting...")
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

def main():
    """Script entry point.
    """
    initlogging()
    log.setLevel(logging.DEBUG)
    l = startlisteners(Config())
    if Config().redirection:
        redirection(ModuleConfig("redirection.conf"), l)
    wait()
    
if __name__ == '__main__':
    main()
    
