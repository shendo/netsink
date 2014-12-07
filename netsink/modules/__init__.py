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

import pkg_resources

# Mapping of known module names -> Handler class
registry = {}

# insert core modules in case running form source / uninstalled
from netsink.modules.http import HTTPHandler
from netsink.modules.sslwrap import SSLHandler
from netsink.modules.smtp import SMTPHandler
registry['http'] = HTTPHandler
registry['ssl'] = SSLHandler
registry['smtp'] = SMTPHandler
# ignore if third-party dependencies not met
try:
    from netsink.modules.dns import DNSHandler
    registry['dns'] = DNSHandler
except ImportError:
    pass
try:
    from netsink.modules.ircserver import IRCHandler
    registry['irc'] = IRCHandler
except ImportError:
    pass
try:
    from netsink.modules.ftp import FTPHandler
    registry['ftp'] = FTPHandler
except ImportError:
    pass

# load any installed modules from entrypoints
for modules in pkg_resources.iter_entry_points(group='netsink.modules'):
    registry[modules.name] = modules.load()
