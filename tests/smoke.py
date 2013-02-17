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

import socket
import urllib2

from dnslib import DNSRecord, DNSQuestion

from netsink.config import Config
import start

if __name__ == '__main__':
    print "Netsink smoke test"
    print "------------------"
    start.startlisteners(Config())
    
    print "+ 10,000 dns lookups (sequential) ",
    localaddress = socket.gethostbyname(socket.gethostname())
    for x in range(10000):
        resp = DNSRecord(q=DNSQuestion("google.com")).send("127.0.0.1")
        assert str(resp.get_a().rdata) == localaddress
        if not x % 1000:
            print ".",
    print "[OK]"
        
    print "+ 10,000 http requests (sequential) ",
    for x in range(10000):
        resp = urllib2.urlopen("http://127.0.0.1/anything").read()
        assert "Netsink" in resp
        if not x % 1000:
            print ".",
    print "[OK]"
    
    print "+ 10,000 https requests (sequential) ",
    for x in range(10000):
        resp = urllib2.urlopen("https://127.0.0.1/anything/else").read()
        assert "Netsink" in resp
        if not x % 1000:
            print ".",
    print "[OK]"
    
    