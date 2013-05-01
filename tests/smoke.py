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

import email.utils
from email.mime.text import MIMEText
import smtplib
import socket
import urllib2

from dnslib import DNSRecord, DNSQuestion

from netsink.config import Config
import netsink.start as netsink

LOCALADDR = socket.gethostbyname(socket.gethostname())

def runtest(testfunc, desc, repeats):
    """Execute the defined no args testfunc, 'repeats' number of times."""
    print "+ %i %s (sequential)" % (repeats, desc),
    for x in range(repeats):
        testfunc()
        if not x % (repeats / 10):
            print ".",
    print "[OK]"
    
def dns():
    resp = DNSRecord(q=DNSQuestion("google.com")).send("127.0.0.1")
    assert str(resp.get_a().rdata) == LOCALADDR

def http():
    resp = urllib2.urlopen("http://127.0.0.1/anything").read()
    assert "Netsink" in resp

def https():
    resp = urllib2.urlopen("https://127.0.0.1/anything/else").read()
    assert "Netsink" in resp

def smtp():
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    server = smtplib.SMTP('127.0.0.1', 25)
    #server.set_debuglevel(True)
    try:
        server.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    finally:
        server.quit()
        
if __name__ == '__main__':
    print "Netsink smoke test"
    print "------------------"
    netsink.startlisteners(Config())
    
    rpts = 10000
    runtest(dns, "dns lookups", rpts)
    runtest(http, "http requests", rpts)
    runtest(https, "https requests", rpts)
    runtest(smtp, "smtp mail sends", rpts)
    
    