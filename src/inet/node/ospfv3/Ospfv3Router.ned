//
// Copyright (C) 2005 Andras Babos
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//


package inet.node.ospfv3;

import inet.node.inet.Router;


//
// An OSPFv3 router.
//
module Ospfv3Router extends Router
{
    parameters:
        hasIpv6 = true;
        *.routingTableModule6 = "^.ipv6.routingTable";
        hasOspf = true;
        ospf.typename = "Ospfv3";
}

