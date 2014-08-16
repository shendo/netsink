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

import email.utils
from email.mime.text import MIMEText
import smtplib
import socket
import urllib2

from dnslib import DNSRecord, DNSQuestion
import irc.client

from netsink.config import Config
import netsink.start as netsink

LOCALADDR = socket.gethostbyname(socket.gethostname())

def runtest(testfunc, desc, repeats):
    """Execute the defined no args testfunc, 'repeats' number of times."""
    print "+ %i %s (sequential)" % (repeats, desc),
    for x in range(repeats):
        testfunc()
        if not x % max(1, int(repeats / 10)):
            print ".",
    print "[OK]"
    
def dnstest():
    resp = DNSRecord(q=DNSQuestion("google.com")).send("127.0.0.1")
    assert str(resp.get_a().rdata) == LOCALADDR

def httptest():
    resp = urllib2.urlopen("http://127.0.0.1/anything").read()
    assert "Netsink" in resp

def httpstest():
    resp = urllib2.urlopen("https://127.0.0.1/anything/else").read()
    assert "Netsink" in resp

def smtptest():
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

def irctest():
    client = irc.client.IRC()
    server = client.server().connect("127.0.0.1", 6667, "netsink")
    server.join("#testchan", key="12345")
    server.privmsg("#testchan", "ready for tasking")
    # drain response messages
    for _ in range(6):
        client.process_once(0.015)
    server.close()    
    
    
if __name__ == '__main__':
    print "Netsink smoke test"
    print "------------------"
    netsink.startlisteners(Config())
    
    runtest(dnstest, "dns lookups", 10000)
    runtest(httptest, "http requests", 10000)
    runtest(httpstest, "https requests", 10000)
    runtest(smtptest, "smtp mail sends", 10000)
    runtest(irctest, "irc sessions", 1000)

