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

import logging
import os
import shutil
import socket
import tempfile

from pyftpdlib import log
logger = logging.getLogger(__name__)
log.logger = logger

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler as PyFTPHandler
from pyftpdlib.ioloop import IOLoop
    
from netsink import get_data_file
from netsink.config import parseints
from netsink.listener import StreamHandler
from netsink.version import __version__

class PermissiveAuthorizer(DummyAuthorizer):
    """Overriden Authorizer to accept any user/password.
    It is expected to be instantiated on a per handler basis
    not as a class attribute as with pyftpd.
    """
    def __init__(self, homedir):
        """Specify the home drive for the user"""
        self.homedir = homedir
        
    def validate_authentication(self, username, password, handler):
        """All are welcome"""
        handler.log("Username: '{0}' Password: '{1}'".format(username, password))
        return True
    
    def get_home_dir(self, username):
        """The temp home dir for the current user"""
        return self.homedir
    
    def has_user(self, username):
        """Any user is known"""
        return True
    
    def has_perm(self, username, perm, path=None):
        """Any user has full perms under the current homedir"""
        if not path:
            return True
        
        path = os.path.normcase(path)
        if self._issubpath(path, self.homedir):
            return True
        return False
    
    def get_perms(self, username):
        """Full perms list"""
        return "elradfmwM"
    
    def get_msg_login(self, username):
        """Default login message."""
        return "Login successful."

    def get_msg_quit(self, username):
        """Default quitting message."""
        return "Goodbye."


class FTPHandler(StreamHandler):
    """FTP Handler that proxies to pyftpdlib.
    """
    version = __version__

    def config(self, config):
        self.dirseed = config.get('ftp', 'dirseed')
        PyFTPHandler.banner = config.get('ftp', 'serverstring')
        PyFTPHandler.passive_ports = list(parseints(config.get('ftp', 'pasvrange')))

    def handle(self):
        """Hands control off to pyftpd to process the client connection.
        """
        # server attributes/methods expected by pyftp handler
        self.server.backlog = 50
        self.server.ip_map = []
        self.server._accept_new_cons = lambda: True
        self.server._af = socket.AF_INET
        tmpdir = None
        try:
            # set up a temp dir as the ftp root for the user
            tmpdir = tempfile.mkdtemp(prefix='tmpftp')
            ftproot = os.path.join(tmpdir, self.dirseed).decode('utf-8')
            shutil.copytree(get_data_file(self.dirseed), ftproot)
            # hand off control to their handler with its own async ioloop
            handler = PyFTPHandler(self.request, self.server, ioloop=IOLoop())
            handler.authorizer = PermissiveAuthorizer(ftproot)
            handler.handle()
            handler.ioloop.loop(1)
        finally:
            if handler.ioloop:
                handler.ioloop.close()
            if tmpdir:
                shutil.rmtree(tmpdir)
