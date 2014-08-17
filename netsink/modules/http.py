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

from datetime import datetime
import logging
import mimetypes
import os
from collections import namedtuple
import re

from netsink import get_data_file
from netsink.listener import StreamHandler
from netsink.version import __version__

class HTTPHandler(StreamHandler):
    """Basic HTTP support.  Serves up static content as specified in conf file.
    """
    version = __version__
    
    @staticmethod
    def match(data):
        return re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE) \S+ HTTP/1\.[01]\r\n', data)
    
    def config(self, config):
        self. responses = []
        for x in config.get('http', 'responses').split(","):
            resp = namedtuple('response', 'pattern status file')
            resp.name = x.strip()
            resp.pattern = config.get(resp.name, 'pattern')
            resp.status = config.get(resp.name, 'status')
            resp.file = config.get(resp.name, 'file')
            self.responses.append(resp)
        self.serverstring = config.get('http', 'serverstring')
        
    def handle(self):
        """Read request from stream and return appropriate response.
        """
        # keep reading to end of http header
        data = ""
        while True:
            header = self.rfile.readline()
            if not header:
                return
            data += header
            if data.endswith('\r\n\r\n'):
                break
        
        # read (and ignore) any body
        m = re.search("Content-Length: (?P<length>\d+)\r\n", data)
        if m:
            self.rfile.read(int(m.group('length')))
        # handle request
        host = ""
        m = re.search(r"Host: (?P<host>[0-9a-zA-Z\-\.\:]+)\r\n", data)
        if m:
            host = m.group('host').lower() # normalise
        m = re.match(r"^(?P<method>\w+) (?P<path>\S+) (?P<version>HTTP/\d\.\d)\r\n", data)
        if m:
            self.handlepath(host, m.group('method'), m.group('path'))
            
    def handlepath(self, host, method, path):
        """Search config patterns to find an appropriate file/response to return.
        """
        for x in self.responses:
            m = re.match(x.pattern, host + path)
            if m:
                data = ""
                if x.file and x.file != "None":
                    if not os.path.exists(get_data_file(x.file)):
                        logging.warn("Cannot find referenced file: %s to return for http request", x.file)
                    else:
                        with open(get_data_file(x.file), 'rb') as tmp:
                            data = tmp.read()
                self.wfile.write("HTTP/1.0 %s OK\r\n" % x.status)
                self.wfile.write("Date: %s\r\n" %  datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
                self.wfile.write("Server: %s\r\n" % self.serverstring)
                self.wfile.write("Connection: close\r\n")
                if data:
                    self.wfile.write("Content-Length: %s\r\n" % len(data))
                    self.wfile.write("Content-Type: %s\r\n\r\n" % mimetypes.guess_type(x.file)[0])
                    self.wfile.write(data)
                else:
                    self.wfile.write("\r\n")
                return
                
