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

import os
from pkg_resources import DistributionNotFound, ResourceManager, Requirement

# path to data files if package not installed
SOURCE_PATH = os.path.join(os.path.dirname(__file__), 'data')

def get_data_file(filename):
    """Return full path to specified data file or None if not found.
    If a valid absolute path is provided it will be returned.
    """
    if os.path.exists(filename):
        return filename
    path = os.path.join(SOURCE_PATH, filename)
    if os.path.exists(path):
        return path
    try:
        return ResourceManager().resource_filename(Requirement.parse("netsink"), filename)
    except DistributionNotFound:
        return None
