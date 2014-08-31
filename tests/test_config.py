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

from netsink.config import parseints

def test_intlist():
    assert [] == list(parseints(''))
    assert [1] == list(parseints('1'))
    assert [1] == list(parseints(' 1 '))
    assert [1, 2, 3] == list(parseints('1,2,3'))
    assert [5, 6, 7, 8] == list(parseints('5-8'))
    assert [2, 3, 4, 5, 7, 8, 9, 10] == list(parseints(' 2, 3,4,5- 5 ,7-9,10'))
    assert [0] == list(parseints('0'))
    assert [1100, 1101, 1102, 1103] == list(parseints('1100-1103'))
    