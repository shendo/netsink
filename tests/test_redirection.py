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

from netsink.redirection import Redirector

def test_rules():
    redir = Redirector()
    redir.localaddr = "1.2.3.4"
    
    assert "-j DNAT -p tcp -m multiport --destination-ports 123 --to-destination 1.2.3.4:555" == \
        redir._create_nat_rule("tcp", [123], 555)
    assert "-j DNAT -p tcp -m multiport --destination-ports 123,456 --to-destination 1.2.3.4:555" == \
        redir._create_nat_rule("tcp", [123, 456], 555)
    assert "-j DNAT -p tcp -m multiport --destination-ports 123,456 --to-destination 1.2.3.4" == \
        redir._create_nat_rule("tcp", [123, 456], None)
    assert "-j DNAT -p tcp --to-destination 1.2.3.4:555" == redir._create_nat_rule("tcp", [], outport=555)
    assert "-j DNAT --to-destination 1.2.3.4" == redir._create_nat_rule(None, [], None)
