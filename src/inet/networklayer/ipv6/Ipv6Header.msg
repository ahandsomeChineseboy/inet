//
// Copyright (C) 2005 Wei Yang, Ng
// Copyright (C) 2005 Andras Varga
// Copyright (C) 2001-2004 CTIE, Monash University
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this program; if not, see <http://www.gnu.org/licenses/>.
//

import inet.common.INETDefs;
import inet.networklayer.common.IpProtocolId;
import inet.networklayer.contract.NetworkHeaderBase;
import inet.networklayer.contract.ipv6.Ipv6Address;

cplusplus {{
#include <iostream>
}}


namespace inet;

cplusplus {{
class Ipv6ExtensionHeader;
std::ostream& operator<<(std::ostream& os, Ipv6ExtensionHeader eh);

const int IPv6_HEADER_BYTES = 40;
}}

//
// This serves as the base class for all the Ipv6 extension headers.
//
class Ipv6ExtensionHeader extends cObject
{
    short extensionType;
    short byteLength = 0;   // byteLength = n * 8;
}

//
// Ipv6 datagram. RFC 2460 Section 3.
//
// Header fields not explicitly modelled:
//    - version (=6): represented by the class name itself
//    - payload length: will be calculated from encapsulated message length
//      and extension headers' length
//
class Ipv6Header extends NetworkHeaderBase
{
    @customize;
    chunkLength = B(IPv6_HEADER_BYTES);
    Ipv6Address srcAddress;
    Ipv6Address destAddress;
    int payloadLength = -1;    // The size of the payload in octets, including any extension headers. The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option.
    unsigned char trafficClass;
    abstract int diffServCodePoint;  // maps to bits 0-5 of trafficClass
    abstract int explicitCongestionNotification;  // maps to bits 6-7 of trafficClass
    unsigned int flowLabel;
    short hopLimit = 0;
    IpProtocolId protocolId = IP_PROT_NONE;

    abstract Ipv6ExtensionHeader *extensionHeader[]; // array of extension headers, subclassed from ~Ipv6ExtensionHeader
}

