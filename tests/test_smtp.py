# Netsink - Network Sinkhole for Isolated Malware Analysis
# Copyright (C) 2013-2014 Steve Henderson
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
import SocketServer
import smtplib
import thread

from netsink.config import ModuleConfig
from netsink.modules import smtp

def test_smtp():
    server = SocketServer.TCPServer(('', 0), smtp.SMTPHandler)
    server.cfg = ModuleConfig('smtp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = smtplib.SMTP('127.0.0.1', server.socket.getsockname()[1])
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    # returns dictionary of failed recipients
    assert not client.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    client.quit()

def test_smtp_auth_plain():
    server = SocketServer.TCPServer(('', 0), smtp.SMTPHandler)
    server.cfg = ModuleConfig('smtp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = smtplib.SMTP('127.0.0.1', server.socket.getsockname()[1])
    client.set_debuglevel(True)
    client.login('testuser', 'secret')
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    # returns dictionary of failed recipients
    assert not client.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    client.quit()

def test_smtp_auth_login():
    server = SocketServer.TCPServer(('', 0), smtp.SMTPHandler)
    server.cfg = ModuleConfig('smtp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = smtplib.SMTP('127.0.0.1', server.socket.getsockname()[1])
    client.set_debuglevel(True)
    client.ehlo()
    # force to use login
    client.esmtp_features['auth'] = 'LOGIN'
    client.login('testuser', 'secret')
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    # returns dictionary of failed recipients
    assert not client.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    client.quit()

    
def test_smtp_starttls():
    server = SocketServer.TCPServer(('', 0), smtp.SMTPHandler)
    server.cfg = ModuleConfig('smtp.conf').cfg
    thread.start_new_thread(server.serve_forever, ())
    client = smtplib.SMTP('127.0.0.1', server.socket.getsockname()[1])
    client.set_debuglevel(True)
    client.ehlo()
    client.starttls()
    msg = MIMEText('Message Body')
    msg['To'] = email.utils.formataddr(('Recipient', 'netsink@example.com'))
    msg['From'] = email.utils.formataddr(('Author', 'test@example.com'))
    msg['Subject'] = 'Netsink Test Message'
    # returns dictionary of failed recipients
    assert not client.sendmail('test@example.com', 
                        ['netsink@example.com'], 
                        msg.as_string())
    client.quit()
