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

import atexit
import logging
import socket
import subprocess

log = logging.getLogger(__name__)

class Redirector(object):
    """Uses iptables for setting up DNAT connection/port forwarding rules.
    
    Command-line is used over 'python-iptables' package due to version issues 
    encountered with different linux flavours.
    
    Any created rules will be automatically deregistered on clean interpreter exit.
    """
    def __init__(self):
        self.localaddr = socket.gethostbyname(socket.gethostname())
        self.rules = []
        atexit.register(self.remove_all_forwarding)
        
    @staticmethod
    def available():
        """Returns true if connection redirection is supported on the current platform.
        false otherwise.
        """
        try:
            subprocess.check_call("iptables -L".split())
            return True
        except (subprocess.CalledProcessError, WindowsError):
            return False
    
    @staticmethod
    def existing_rules():
        """Returns true if there are existing iptables rules which may cause
        conflict with the connection redirection/forwarding, false otherwise.
        """
        try:
            stdout, _ = subprocess.Popen("iptables -L".split(), 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            for x in stdout.splitlines():
                if x and not x.startswith('Chain') and not x.startswith('target'):
                    return True
        except (subprocess.CalledProcessError, WindowsError):
            pass # fall through
        return False
        
    def add_forwarding(self, protocol=None, inports=[], outport=None):
        """Attempt to add a forwarding rule for the specified connection details.
        """ 
        cmd = "iptables -t nat -A PREROUTING %s" % self._create_nat_rule(protocol, inports, outport)
        log.debug(cmd)
        subprocess.check_call(cmd.split())
        self.rules.append((protocol, inports, outport))
    
    def remove_forwarding(self, protocol=None, inports=[], outport=None):
        """Attempt to remove any forwarding rule for the specified connection details.
        """
        cmd = "iptables -t nat -D PREROUTING %s" % self._create_nat_rule(protocol, inports, outport)
        log.debug(cmd)
        subprocess.check_call(cmd.split())
        self.rules.remove((protocol, inports, outport))
    
    def remove_all_forwarding(self):
        """Attempt to remove all added forwarding rules performed via this Redirector.
        """
        log.info("Cleaning up all forwarding rules...")
        for protocol, inports, outport in list(self.rules):
            self.remove_forwarding(protocol, inports, outport)
    
    def _create_nat_rule(self, protocol, inports, outport):
        """Builds the corresponding rule string for use with iptables.
        """
        inports = [ str(x) for x in inports ] # convert to strings 
        rule = "-j DNAT "
        if protocol:
            rule += "-p %s " % protocol
            
        if inports and outport:
            rule += "-m multiport --destination-ports %s --to-destination %s:%s" % \
                (",".join(inports), self.localaddr, outport)
        elif inports:
            rule += "-m multiport --destination-ports %s --to-destination %s" % \
                (",".join(inports), self.localaddr)
        elif outport:
            rule += "--to-destination %s:%s" % \
                (self.localaddr, outport)
        else:
            rule += "--to-destination %s" % self.localaddr
        return rule
    
    
