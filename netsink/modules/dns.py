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

from collections import namedtuple
import logging
import re
import socket

from dnslib import DNSRecord, QTYPE

from netsink.listener import UDPHandler
from netsink.version import __version__

log = logging.getLogger(__name__)

class DNSHandler(UDPHandler):
    """Basic DNS server.  Answers returned as specified in conf file.
    """
    version = __version__
    
    def config(self, config):
        self.responses = []
        for x in config.get('dns', 'responses').split(","):
            resp = namedtuple('response', 'pattern types response')
            resp.name = x.strip()
            resp.pattern = config.get(resp.name, 'pattern')
            resp.types = [ t.strip() for t in config.get(resp.name, 'types').split(",") ]
            resp.answer = config.get(resp.name, 'answer')
            if resp.answer == 'localhost':
                resp.answer = socket.gethostbyname(socket.gethostname())
            self.responses.append(resp)
        
    def handle(self):
        """Parse request from datagram and return appropriate response.
        """
        # read datagram
        d = DNSRecord.parse(self.rfile.read())
        q = d.get_q()
        for x in self.responses:
            m = re.match(x.pattern, str(q.qname))
            if m and QTYPE[q.qtype] in x.types:
                if x.answer == 'NXDOMAIN':
                    break
                log.info("Received DNS Query %s Type: %s. Responding with %s", 
                         q.qname, QTYPE[q.qtype], x.answer)
                a = d.reply(data=x.answer)
                self.wfile.write(a.pack())
                return
        # nothing matched, send an NXDOMAIN
        log.info("Received DNS Query: %s Type: %s. Responding with NXDOMAIN", 
                     q.qname, QTYPE[q.qtype])
        a = d.reply()
        a.rr = []
        a.header.set_rcode(3)
        self.wfile.write(a.pack())
                