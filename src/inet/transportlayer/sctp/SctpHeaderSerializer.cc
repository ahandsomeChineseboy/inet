//
// Copyright (C) 2005 Christian Dankbar, Irene Ruengeler, Michael Tuexen, Andras Varga
// Copyright (C) 2010 Thomas Dreibholz
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/common/Endian.h"
#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/networklayer/common/IpProtocolId_m.h"
#include "inet/networklayer/ipv4/headers/ip.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4HeaderSerializer.h"
#include "inet/transportlayer/contract/sctp/SctpCommand_m.h"
#include "inet/transportlayer/sctp/SctpAssociation.h"
#include "inet/transportlayer/sctp/SctpChecksum.h"
#include "inet/transportlayer/sctp/SctpHeaderSerializer.h"
#include "inet/transportlayer/sctp/headers/sctphdr.h"


#if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)
#include <netinet/in.h>    // htonl, ntohl, ...
#include <arpa/inet.h>
#include <sys/socket.h>
#endif // if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)

#include <sys/types.h>
#define MAXBUFLEN 1<<16
#define PAD_LEN(x) ((4 - (x & 3)) & 3)

namespace inet {

namespace sctp {

Register_Serializer(SctpHeader, SctpHeaderSerializer);

namespace {

// TODO: chunks must be padded to 4 bytes boundary, padding should not be included in the length field

void serializeDataChunk(MemoryOutputStream& stream, const SctpDataChunk* dataChunk) {
    // RFC 4960, 3.3.1., RFC 7053, 3.
    /**
     * Type: 8 bits
     * Reserved: 4 bits
     * I bit: 1 bit
     * U bit: 1 bit
     * B bit: 1 bit
     * E bit: 1 bit
     * Length: 16 bits (length of data chunk in bytes without padding)
     * TSN: 32 bits
     * Stream Identifier (S): 16 bits
     * Stream Sequence Number (n): 16 bits
     * Payload Protocol Identifier: 32 bits
     * User Data: variable length
     */
    stream.writeByte(dataChunk->getSctpChunkType());
    stream.writeNBitsOfUint64Be(0, 4);
    stream.writeBit(dataChunk->getIBit());
    stream.writeBit(dataChunk->getUBit());
    stream.writeBit(dataChunk->getBBit());
    stream.writeBit(dataChunk->getEBit());
    stream.writeUint16Be(dataChunk->getByteLength());
    stream.writeUint32Be(dataChunk->getTsn());
    stream.writeUint16Be(dataChunk->getSid());
    stream.writeUint16Be(dataChunk->getSsn());
    stream.writeUint32Be(dataChunk->getPpid());
    SctpSimpleMessage *smsg = check_and_cast<SctpSimpleMessage *>(dataChunk->getEncapsulatedPacket());
    const uint32_t datalen = smsg->getDataLen();
    ASSERT(datalen == dataChunk->getByteLength() - 16);
    if (smsg->getDataArraySize() >= datalen) {
        for (uint32_t i = 0; i < datalen; ++i) {
            stream.writeByte(smsg->getData(i));
        }
    }
    // TODO: padding to 4 bytes boundary
    //stream.writeByteRepeatedly(0, PAD_LEN(16 + datalen));
}

void deserializeDataChunk(MemoryInputStream& stream, SctpDataChunk* dataChunk) {
    B startPos = stream.getRemainingLength();
    dataChunk->setSctpChunkType(DATA);
    stream.readNBitsToUint64Be(4);
    dataChunk->setIBit(stream.readBit());
    dataChunk->setUBit(stream.readBit());
    dataChunk->setBBit(stream.readBit());
    dataChunk->setEBit(stream.readBit());
    uint16_t length = stream.readUint16Be();
    dataChunk->setLength(length);
    dataChunk->setTsn(stream.readUint32Be());
    dataChunk->setSid(stream.readUint16Be());
    dataChunk->setSsn(stream.readUint16Be());
    dataChunk->setPpid(stream.readUint32Be());
    const uint32_t datalen = length - (B(startPos - stream.getRemainingLength()).get() + 1);    // +1 because the type is read before the initialization of the startPos variable
    if (datalen > 0) {
        SctpSimpleMessage *smsg = new SctpSimpleMessage("data");
        smsg->setBitLength(datalen * 8);
        smsg->setDataLen(datalen);
        smsg->setDataArraySize(datalen);
        for (uint32_t i = 0; i < datalen; ++i) {
            smsg->setData(i, stream.readByte());
        }
        dataChunk->encapsulate(smsg);
    }
    dataChunk->setByteLength(length);
    // TODO: padding??
}

void serializeInitChunk(MemoryOutputStream& stream, const SctpInitChunk* initChunk) {
    // RFC 4960, 3.3.2.
    /**
     * Type: 8 bits
     * Chunk Flags: 8 bits
     * Length: 16 bits (length of data chunk in bytes without padding)
     * Initiate Tag: 32 bits
     * a_rwnd: 32 bits
     * Number of Outbound Streams: 16 bits
     * Number of Inbound Streams: 16 bits
     * Initial TSN: 32 bits
     * Optional/Variable-Length Parameters: variable length
     */
    stream.writeByte(initChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(initChunk->getByteLength());
    stream.writeUint32Be(initChunk->getInitTag());
    stream.writeUint32Be(initChunk->getA_rwnd());
    stream.writeUint16Be(initChunk->getNoOutStreams());
    stream.writeUint16Be(initChunk->getNoInStreams());
    stream.writeUint32Be(initChunk->getInitTsn());
    // Supported Address Types Parameter (RFC 4960, 3.3.2.1.)
    if (initChunk->getIpv4Supported() || initChunk->getIpv6Supported()) {
        stream.writeUint16Be(INIT_SUPPORTED_ADDRESS);
        stream.writeUint16Be(initChunk->getIpv4Supported() && initChunk->getIpv6Supported() ? 8 : 6);
        if (initChunk->getIpv4Supported() && initChunk->getIpv6Supported()) {
            stream.writeUint16Be(INIT_PARAM_IPV4);
            stream.writeUint16Be(INIT_PARAM_IPV6);
        }
        else if (initChunk->getIpv4Supported())
            stream.writeUint16Be(INIT_PARAM_IPV4);
        else
            stream.writeUint16Be(INIT_PARAM_IPV6);
        // TODO: padding to 4 bytes
    }
    // Forward-TSN-Supported Parameter (RFC 3758, 3.1.)
    if (initChunk->getForwardTsn() == true) {
        stream.writeUint16Be(FORWARD_TSN_SUPPORTED_PARAMETER);
        stream.writeUint16Be(4);
    }
    // IPv4 Address Parameter & IPv6 Address Parameter (RFC 4960, 3.3.2.1.)
    for (size_t i = 0; i < initChunk->getAddressesArraySize(); ++i) {
        if (initChunk->getAddresses(i).getType() == L3Address::IPv4) {
            stream.writeUint16Be(INIT_PARAM_IPV4);
            stream.writeUint16Be(8);
            stream.writeIpv4Address(initChunk->getAddresses(i).toIpv4());
        }
        else if (initChunk->getAddresses(i).getType() == L3Address::IPv6) {
            stream.writeUint16Be(INIT_PARAM_IPV6);
            stream.writeUint16Be(20);
            stream.writeIpv6Address(initChunk->getAddresses(i).toIpv6());
        }
    }
    // Supported Extensions Parameter (RFC 5061, 4.2.7.)
    uint64_t chunkCount = initChunk->getSepChunksArraySize();
    if (chunkCount > 0) {
        stream.writeUint16Be(SUPPORTED_EXTENSIONS);
        stream.writeUint16Be(4 + chunkCount);
        for (uint64_t i = 0; i < chunkCount; ++i) {
            stream.writeByte(initChunk->getSepChunks(i));
        }
        // TODO: padding to 4 bytes
    }
    // Random Parameter (RFC 4895, 3.1.)
    uint64_t randomCount = initChunk->getRandomArraySize();
    if (randomCount > 0) {
        stream.writeUint16Be(RANDOM);
        stream.writeUint16Be(4 + randomCount);
        for (uint64_t i = 0; i < randomCount; ++i) {
            stream.writeByte(initChunk->getRandom(i));
        }
        // TODO: padding to 4 bytes
    }
    // Chunk List Parameter (RFC 4895, 3.2.)
    uint64_t chunkTypeCount = initChunk->getSctpChunkTypesArraySize();
    if (chunkTypeCount > 0) {
        stream.writeUint16Be(CHUNKS);
        stream.writeUint16Be(4 + chunkTypeCount);
        for (uint64_t i = 0; i < chunkTypeCount; ++i) {
            stream.writeByte(initChunk->getSctpChunkTypes(i));
        }
        // TODO: padding to 4 bytes
    }
    // Requested HMAC Algorithm Parameter (RFC 4895, 3.3.)
    uint64_t hmacCount = initChunk->getHmacTypesArraySize();
    if (hmacCount > 0) {
        stream.writeUint16Be(HMAC_ALGO);
        stream.writeUint16Be(4 + 2 * hmacCount);
        for (uint64_t i = 0; i < hmacCount; ++i) {
            stream.writeUint16Be(initChunk->getHmacTypes(i));
        }
        // TODO: padding to 4 bytes
    }
}

void deserializeInitChunk(MemoryInputStream& stream, SctpInitChunk *initChunk) {
    initChunk->setSctpChunkType(INIT);
    stream.readByte();
    initChunk->setByteLength(stream.readUint16Be());
    initChunk->setInitTag(stream.readUint32Be());
    initChunk->setA_rwnd(stream.readUint32Be());
    initChunk->setNoOutStreams(stream.readUint16Be());
    initChunk->setNoInStreams(stream.readUint16Be());
    initChunk->setInitTsn(stream.readUint32Be());
    uint64_t readBytes = 20;
    while (readBytes < uint64_t(initChunk->getByteLength())) {
        uint16_t chunkType = stream.readUint16Be();
        uint16_t length = stream.readUint16Be();
        readBytes += length;
        //std::cout << "readBytes: " << readBytes << endl;
        switch (chunkType) {
            case INIT_SUPPORTED_ADDRESS: {
                for (uint8_t i = 0; i < length - 4; i += 2) {
                    uint16_t tmp = stream.readUint16Be();
                    if (tmp == INIT_PARAM_IPV4)
                        initChunk->setIpv4Supported(true);
                    else if (tmp == INIT_PARAM_IPV6)
                        initChunk->setIpv6Supported(true);
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case FORWARD_TSN_SUPPORTED_PARAMETER: {
                initChunk->setSepChunksArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initChunk->setSepChunks(i, stream.readByte());
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case INIT_PARAM_IPV4: {
                initChunk->setAddressesArraySize(initChunk->getAddressesArraySize() + 1);
                Ipv4Address addr = stream.readIpv4Address();
                initChunk->setAddresses(initChunk->getAddressesArraySize() - 1, addr);
                break;
            }
            case INIT_PARAM_IPV6: {
                initChunk->setAddressesArraySize(initChunk->getAddressesArraySize() + 1);
                initChunk->setAddresses(initChunk->getAddressesArraySize() - 1, stream.readIpv6Address());
                break;
            }
            case SUPPORTED_EXTENSIONS: {
                initChunk->setSepChunksArraySize(length - 4);
                for (uint16_t i = 0; i < uint16_t(length - 4); ++i) {
                    initChunk->setSepChunks(i, stream.readByte());
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case RANDOM: {
                initChunk->setRandomArraySize(length - 4);
                for (uint16_t i = 0; i < uint16_t(length - 4); ++i) {
                    initChunk->setRandom(i, stream.readByte());
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case CHUNKS: {
                initChunk->setSctpChunkTypesArraySize(length - 4);
                for (uint16_t i = 0; i < uint16_t(length - 4); ++i) {
                    initChunk->setSctpChunkTypes(i, stream.readByte());
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case HMAC_ALGO: {
                initChunk->setHmacTypesArraySize((length - 4) / 2);
                for (uint16_t i = 0; i < uint16_t((length - 4) / 2); ++i) {
                    initChunk->setHmacTypes(i, stream.readUint16Be());
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            default: {
                break;
            }
        }
    }
}

void serializeInitAckChunk(MemoryOutputStream& stream, const SctpInitAckChunk* initAckChunk) {
    stream.writeByte(initAckChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(initAckChunk->getByteLength());
    stream.writeUint32Be(initAckChunk->getInitTag());
    stream.writeUint32Be(initAckChunk->getA_rwnd());
    stream.writeUint16Be(initAckChunk->getNoOutStreams());
    stream.writeUint16Be(initAckChunk->getNoInStreams());
    stream.writeUint32Be(initAckChunk->getInitTsn());
    // Supported Address Types Parameter
    if (initAckChunk->getIpv4Supported() || initAckChunk->getIpv6Supported()) {
        stream.writeUint16Be(INIT_SUPPORTED_ADDRESS);
        stream.writeUint16Be(initAckChunk->getIpv4Supported() && initAckChunk->getIpv6Supported() ? 8 : 6);
        if (initAckChunk->getIpv4Supported() && initAckChunk->getIpv6Supported()) {
            stream.writeUint16Be(INIT_PARAM_IPV4);
            stream.writeUint16Be(INIT_PARAM_IPV6);
        }
        else if (initAckChunk->getIpv4Supported())
            stream.writeUint16Be(INIT_PARAM_IPV4);
        else
            stream.writeUint16Be(INIT_PARAM_IPV6);
        // TODO: padding to 4 bytes
    }
    // Forward-TSN-Supported Parameter
    if (initAckChunk->getForwardTsn() == true) {
        stream.writeUint16Be(FORWARD_TSN_SUPPORTED_PARAMETER);
        stream.writeUint16Be(4);
    }
    // IPv4 Address Parameter & IPv6 Address Parameter
    int32_t numaddr = initAckChunk->getAddressesArraySize();
    for (int32_t i = 0; i < numaddr; i++) {
        if (initAckChunk->getAddresses(i).getType() == L3Address::IPv4) {
            stream.writeUint16Be(INIT_PARAM_IPV4);
            stream.writeUint16Be(8);
            stream.writeIpv4Address(initAckChunk->getAddresses(i).toIpv4());
        }
        else if (initAckChunk->getAddresses(i).getType() == L3Address::IPv6) {
            stream.writeUint16Be(INIT_PARAM_IPV6);
            stream.writeUint16Be(20);
            stream.writeIpv6Address(initAckChunk->getAddresses(i).toIpv6());
        }
    }
    // Supported Extensions Parameter
    uint64_t chunkCount = initAckChunk->getSepChunksArraySize();
    if (chunkCount > 0) {
        stream.writeUint16Be(SUPPORTED_EXTENSIONS);
        stream.writeUint16Be(4 + chunkCount);
        for (uint64_t i = 0; i < chunkCount; ++i) {
            stream.writeByte(initAckChunk->getSepChunks(i));
        }
    }
    // Unrecognized Parameters
    uint64_t unrecognizedCount = initAckChunk->getUnrecognizedParametersArraySize();
    if (unrecognizedCount > 0) {
        stream.writeUint16Be(UNRECOGNIZED_PARAMETER);
        stream.writeUint16Be(4 + unrecognizedCount);
        for (uint64_t i = 0; i < unrecognizedCount; ++i) {
            stream.writeByte(initAckChunk->getUnrecognizedParameters(i));
        }
    }
    // Random Parameter
    uint64_t randomCount = initAckChunk->getRandomArraySize();
    if (randomCount > 0) {
        stream.writeUint16Be(RANDOM);
        stream.writeUint16Be(4 + randomCount);
        for (uint64_t i = 0; i < randomCount; ++i) {
            stream.writeByte(initAckChunk->getRandom(i));
        }
    }
    // Chunk List Parameter
    uint64_t chunkTypeCount = initAckChunk->getSctpChunkTypesArraySize();
    if (chunkTypeCount > 0) {
        stream.writeUint16Be(CHUNKS);
        stream.writeUint16Be(4 + chunkTypeCount);
        for (uint64_t i = 0; i < chunkTypeCount; ++i) {
            stream.writeByte(initAckChunk->getSctpChunkTypes(i));
        }
    }
    // Requested HMAC Algorithm Parameter
    uint64_t hmacCount = initAckChunk->getHmacTypesArraySize();
    if (hmacCount > 0) {
        stream.writeUint16Be(HMAC_ALGO);
        stream.writeUint16Be(4 + 2 * hmacCount);
        for (uint64_t i = 0; i < hmacCount; ++i) {
            stream.writeUint16Be(initAckChunk->getHmacTypes(i));
        }
    }
    // State Cookie Parameter: FIXME
    if (initAckChunk->getStateCookie() != nullptr) {
        stream.writeUint16Be(7);
        stream.writeUint16Be(initAckChunk->getStateCookie()->getLength());
        stream.writeByteRepeatedly('0', initAckChunk->getStateCookie()->getLength() - 4);
    }
}

void deserializeInitAckChunk(MemoryInputStream& stream, SctpInitAckChunk *initAckChunk) {
    initAckChunk->setSctpChunkType(INIT_ACK);
    stream.readByte();
    initAckChunk->setByteLength(stream.readUint16Be());
    initAckChunk->setInitTag(stream.readUint32Be());
    initAckChunk->setA_rwnd(stream.readUint32Be());
    initAckChunk->setNoOutStreams(stream.readUint16Be());
    initAckChunk->setNoInStreams(stream.readUint16Be());
    initAckChunk->setInitTsn(stream.readUint32Be());
    uint64_t readBytes = 20;
    while (readBytes < uint64_t(initAckChunk->getByteLength())) {
        uint16_t chunkType = stream.readUint16Be();
        uint16_t length = stream.readUint16Be();
        readBytes += length;
        switch (chunkType) {
            case INIT_SUPPORTED_ADDRESS: {
                for (uint8_t i = 0; i < length - 4; i += 2) {
                    uint16_t tmp = stream.readUint16Be();
                    if (tmp == INIT_PARAM_IPV4)
                        initAckChunk->setIpv4Supported(true);
                    else if (tmp == INIT_PARAM_IPV6)
                        initAckChunk->setIpv6Supported(true);
                }
                // TODO: handle padding to 4 bytes
                break;
            }
            case FORWARD_TSN_SUPPORTED_PARAMETER: {
                initAckChunk->setSepChunksArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initAckChunk->setSepChunks(i, stream.readByte());
                }
                break;
            }
            case INIT_PARAM_IPV4: {
                initAckChunk->setAddressesArraySize(initAckChunk->getAddressesArraySize() + 1);
                initAckChunk->setAddresses(initAckChunk->getAddressesArraySize() - 1, stream.readIpv4Address());
                break;
            }
            case INIT_PARAM_IPV6: {
                initAckChunk->setAddressesArraySize(initAckChunk->getAddressesArraySize() + 1);
                initAckChunk->setAddresses(initAckChunk->getAddressesArraySize() - 1, stream.readIpv6Address());
                break;
            }
            case UNRECOGNIZED_PARAMETER: {
                initAckChunk->setUnrecognizedParametersArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initAckChunk->setUnrecognizedParameters(i, stream.readByte());
                }
                break;
            }
            case SUPPORTED_EXTENSIONS: {
                initAckChunk->setSepChunksArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initAckChunk->setSepChunks(i, stream.readByte());
                }
                break;
            }
            case RANDOM: {
                initAckChunk->setRandomArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initAckChunk->setRandom(i, stream.readByte());
                }
                break;
            }
            case CHUNKS: {
                initAckChunk->setSctpChunkTypesArraySize(length - 4);
                for (uint64_t i = 0; i < uint64_t(length - 4); ++i) {
                    initAckChunk->setSctpChunkTypes(i, stream.readByte());
                }
                break;
            }
            case HMAC_ALGO: {
                initAckChunk->setHmacTypesArraySize((length - 4) / 2);
                for (uint64_t i = 0; i < uint64_t((length - 4) / 2); ++i) {
                    initAckChunk->setHmacTypes(i, stream.readUint16Be());
                }
                break;
            }
            // State Cookie Parameter: FIXME
            case 7: {
                SctpCookie *stateCookie = new SctpCookie();
                stateCookie->setLength(length);
                stream.readByteRepeatedly(0, length - 4);
                initAckChunk->setStateCookie(stateCookie);
            }
            default: {
                break;
            }
        }
    }
}

void serializeSackChunk(MemoryOutputStream& stream, const SctpSackChunk* sackChunk) {
    stream.writeByte(sackChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(sackChunk->getByteLength());
    //stream.writeUint64Be(sackChunk->getSackSeqNum());   // FIXME: there is no sack seq num in rfc4960
    //stream.writeUint64Be(sackChunk->getDacPacketsRcvd());   // FIXME: there is no dac packets received in rfc4960
    uint32_t cumtsnack = sackChunk->getCumTsnAck();
    stream.writeUint32Be(cumtsnack);
    stream.writeUint32Be(sackChunk->getA_rwnd());
    uint16_t numgaps = sackChunk->getNumGaps();
    stream.writeUint16Be(numgaps);
    uint16_t numdups = sackChunk->getNumDupTsns();
    stream.writeUint16Be(numdups);
    for (uint16_t i = 0; i < numgaps; ++i) {
        stream.writeUint16Be(sackChunk->getGapStart(i) - cumtsnack);
        stream.writeUint16Be(sackChunk->getGapStop(i) - cumtsnack);
    }
    for (uint16_t i = 0; i < numdups; ++i) {
        stream.writeUint32Be(sackChunk->getDupTsns(i));
    }
}

void deserializeSackChunk(MemoryInputStream& stream, SctpSackChunk *sackChunk) {
    sackChunk->setIsNrSack(false);
    sackChunk->setSctpChunkType(SACK);
    stream.readByte();
    sackChunk->setByteLength(stream.readUint16Be());
    //sackChunk->setSackSeqNum(stream.readUint64Be());   // FIXME: there is no sack seq num in rfc4960
    //sackChunk->setDacPacketsRcvd(stream.readUint64Be());   // FIXME: there is no dac packets received in rfc4960
    uint32_t cumtsnack = stream.readUint32Be();
    sackChunk->setCumTsnAck(cumtsnack);
    sackChunk->setA_rwnd(stream.readUint32Be());
    uint16_t numgaps = stream.readUint16Be();
    sackChunk->setNumGaps(numgaps);
    uint16_t numdups = stream.readUint16Be();
    sackChunk->setNumDupTsns(numdups);
    sackChunk->setGapStartArraySize(numgaps);
    sackChunk->setGapStopArraySize(numgaps);
    for (uint16_t i = 0; i < numgaps; ++i) {
        sackChunk->setGapStart(i, stream.readUint16Be() + cumtsnack);
        sackChunk->setGapStop(i, stream.readUint16Be() + cumtsnack);
    }
    sackChunk->setDupTsnsArraySize(numdups);
    for (uint16_t i = 0; i < numdups; ++i) {
        sackChunk->setDupTsns(i, stream.readUint32Be());
    }
}

void serializeNrSackChunk(MemoryOutputStream& stream, const SctpSackChunk* sackChunk) {
    stream.writeByte(sackChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(sackChunk->getByteLength());
    uint32_t cumtsnack = sackChunk->getCumTsnAck();
    stream.writeUint32Be(cumtsnack);
    stream.writeUint32Be(sackChunk->getA_rwnd());
    uint16_t numgaps = sackChunk->getNumGaps();
    stream.writeUint16Be(numgaps);
    uint16_t numnrgaps = sackChunk->getNumNrGaps();
    stream.writeUint16Be(numnrgaps);
    uint16_t numdups = sackChunk->getNumDupTsns();
    stream.writeUint16Be(numdups);
    stream.writeUint16Be(0);
    for (uint16_t i = 0; i < numgaps; ++i) {
        stream.writeUint16Be(sackChunk->getGapStart(i) - cumtsnack);
        stream.writeUint16Be(sackChunk->getGapStop(i) - cumtsnack);
    }
    for (uint16_t i = 0; i < numnrgaps; ++i) {
        stream.writeUint16Be(sackChunk->getNrGapStart(i) - cumtsnack);
        stream.writeUint16Be(sackChunk->getNrGapStop(i) - cumtsnack);
    }
    for (uint16_t i = 0; i < numdups; ++i) {
        stream.writeUint32Be(sackChunk->getDupTsns(i));
    }
}

void deserializeNrSackChunk(MemoryInputStream& stream, SctpSackChunk *sackChunk) {
    sackChunk->setIsNrSack(true);
    sackChunk->setSctpChunkType(NR_SACK);
    stream.readByte();
    sackChunk->setByteLength(stream.readUint16Be());
    uint32_t cumtsnack = stream.readUint32Be();
    sackChunk->setCumTsnAck(cumtsnack);
    sackChunk->setA_rwnd(stream.readUint32Be());
    uint16_t numgaps = stream.readUint16Be();
    sackChunk->setNumGaps(numgaps);
    uint16_t numnrgaps = stream.readUint16Be();
    sackChunk->setNumNrGaps(numnrgaps);
    uint16_t numdups = stream.readUint16Be();
    sackChunk->setNumDupTsns(numdups);
    sackChunk->setGapStartArraySize(numgaps);
    sackChunk->setGapStopArraySize(numgaps);
    for (uint16_t i = 0; i < numgaps; ++i) {
        sackChunk->setGapStart(i, stream.readUint16Be() + cumtsnack);
        sackChunk->setGapStop(i, stream.readUint16Be() + cumtsnack);
    }
    sackChunk->setNrGapStartArraySize(numnrgaps);
    sackChunk->setNrGapStopArraySize(numnrgaps);
    for (uint16_t i = 0; i < numnrgaps; ++i) {
        sackChunk->setNrGapStart(i, stream.readUint16Be() + cumtsnack);
        sackChunk->setNrGapStop(i, stream.readUint16Be() + cumtsnack);
    }
    sackChunk->setDupTsnsArraySize(numdups);
    for (uint16_t i = 0; i < numdups; ++i) {
        sackChunk->setDupTsns(i, stream.readUint32Be());
    }
}

void serializeHeartbeatChunk(MemoryOutputStream& stream, const SctpHeartbeatChunk* heartbeatChunk) {
    stream.writeByte(heartbeatChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(heartbeatChunk->getByteLength());
    L3Address addr = heartbeatChunk->getRemoteAddr();
    //simtime_t time = heartbeatChunk->getTimeField();  ?? FIXME
    if (addr.getType() == L3Address::IPv4) {
        stream.writeUint16Be(1);    // Heartbeat Info Type=1
        stream.writeUint16Be(12 + 9);   // HB Info Length --- FIXME + 9 because of simtime
        stream.writeUint16Be(INIT_PARAM_IPV4);
        stream.writeUint16Be(8);
        stream.writeIpv4Address(addr.toIpv4());
    }
    else if (addr.getType() == L3Address::IPv6) {
        stream.writeUint16Be(1);    // Heartbeat Info Type=1
        stream.writeUint16Be(24 + 9);   // HB Info Length --- FIXME + 9 because of simtime
        stream.writeUint16Be(INIT_PARAM_IPV6);
        stream.writeUint16Be(20 + 9);
        stream.writeIpv6Address(addr.toIpv6());
    }
    stream.writeSimTime(heartbeatChunk->getTimeField());    // FIXME: definitely not this way
}

void deserializeHeartbeatChunk(MemoryInputStream& stream, SctpHeartbeatChunk *heartbeatChunk) {
    heartbeatChunk->setSctpChunkType(HEARTBEAT);
    stream.readByte();
    heartbeatChunk->setByteLength(stream.readUint16Be());
    stream.readUint16Be();
    uint16_t infolen = stream.readUint16Be();
    uint16_t paramType = stream.readUint16Be();
    stream.readUint16Be();
    switch (paramType) {
        case INIT_PARAM_IPV4: {
            heartbeatChunk->setRemoteAddr(stream.readIpv4Address());
            break;
        }
        case INIT_PARAM_IPV6: {
            heartbeatChunk->setRemoteAddr(stream.readIpv6Address());
            break;
        }
        default:
            stream.readByteRepeatedly(0, infolen - 4);
    }
    heartbeatChunk->setTimeField(stream.readSimTime()); // FIXME: reading the simtime
}

void serializeHeartbeatAckChunk(MemoryOutputStream& stream, const SctpHeartbeatAckChunk* heartbeatAckChunk) {
    stream.writeByte(heartbeatAckChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(heartbeatAckChunk->getByteLength());
    uint32_t infolen = heartbeatAckChunk->getInfoArraySize();
    stream.writeUint16Be(1);
    if (infolen > 0) {
        stream.writeUint16Be(infolen + 4);
        for (uint32_t i = 0; i < infolen; ++i) {
            stream.writeByte(heartbeatAckChunk->getInfo(i));
        }
    }
    else {
        stream.writeUint16Be(0);  // FIXME: writing 0 as length to mandatory field above
        L3Address addr = heartbeatAckChunk->getRemoteAddr();
        if (addr.getType() == L3Address::IPv4) {
            stream.writeUint16Be(1);
            uint32_t infolen = sizeof(addr.toIpv4().getInt()) + sizeof(uint32_t);
            stream.writeUint16Be(infolen + 4);
            stream.writeUint16Be(INIT_PARAM_IPV4);
            stream.writeUint16Be(8);
            stream.writeIpv4Address(addr.toIpv4());
        }
        else if (addr.getType() == L3Address::IPv6) {
            stream.writeUint16Be(1);
            uint32_t infolen = 20 + sizeof(uint32_t);
            stream.writeUint16Be(infolen + 4);
            stream.writeUint16Be(INIT_PARAM_IPV6);
            stream.writeUint16Be(20);
            stream.writeIpv6Address(addr.toIpv6());
        }
    }
    stream.writeSimTime(heartbeatAckChunk->getTimeField());    // FIXME: definitely not this way
}

void deserializeHeartbeatAckChunk(MemoryInputStream& stream, SctpHeartbeatAckChunk *heartbeatAckChunk) {
    heartbeatAckChunk->setSctpChunkType(HEARTBEAT_ACK);
    stream.readByte();
    heartbeatAckChunk->setByteLength(stream.readUint16Be());
    stream.readUint16Be();
    uint16_t infolen = stream.readUint16Be();
    if (infolen == 0) {
        stream.readUint16Be();
        infolen = stream.readUint16Be();
        switch (stream.readUint16Be()) {
            case INIT_PARAM_IPV4: {
                stream.readUint16Be();
                heartbeatAckChunk->setRemoteAddr(stream.readIpv4Address());
                break;
            }
            case INIT_PARAM_IPV6: {
                stream.readUint16Be();
                heartbeatAckChunk->setRemoteAddr(stream.readIpv6Address());
                break;
            }
            default:
                stream.readByteRepeatedly(0, infolen - 4);
        }
    }
    else {
        ASSERT(infolen - 4 >= 0);
        heartbeatAckChunk->setInfoArraySize(infolen - 4);
        for (uint16_t i = 0; i < infolen - 4; ++i) {
            heartbeatAckChunk->setInfo(i, stream.readByte());
        }
    }
    heartbeatAckChunk->setTimeField(stream.readSimTime()); // FIXME: reading the simtime
}

void serializeAbortChunk(MemoryOutputStream& stream, const SctpAbortChunk* abortChunk) {
    stream.writeByte(abortChunk->getSctpChunkType());
    stream.writeNBitsOfUint64Be(0, 7);
    stream.writeBit(abortChunk->getT_Bit());
    stream.writeUint16Be(abortChunk->getByteLength());
    // TODO: zero or more Error Causes?
}

void deserializeAbortChunk(MemoryInputStream& stream, SctpAbortChunk *abortChunk) {
    abortChunk->setSctpChunkType(ABORT);
    stream.readNBitsToUint64Be(7);
    abortChunk->setT_Bit(stream.readBit());
    abortChunk->setByteLength(stream.readUint16Be());
}

void serializeShutdownChunk(MemoryOutputStream& stream, const SctpShutdownChunk* shutdownChunk) {
    stream.writeByte(shutdownChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(shutdownChunk->getByteLength());   // must be 8
    stream.writeUint32Be(shutdownChunk->getCumTsnAck());
}

void deserializeShutdownChunk(MemoryInputStream& stream, SctpShutdownChunk *shutdownChunk) {
    shutdownChunk->setSctpChunkType(SHUTDOWN);
    stream.readByte();
    shutdownChunk->setByteLength(stream.readUint16Be());
    shutdownChunk->setCumTsnAck(stream.readUint32Be());
}

void serializeShutdownAckChunk(MemoryOutputStream& stream, const SctpShutdownAckChunk* shutdownAckChunk) {
    stream.writeByte(shutdownAckChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(shutdownAckChunk->getByteLength());   // must be 4
}

void deserializeShutdownAckChunk(MemoryInputStream& stream, SctpShutdownAckChunk *shutdownAckChunk) {
    shutdownAckChunk->setSctpChunkType(SHUTDOWN_ACK);
    stream.readByte();
    shutdownAckChunk->setByteLength(stream.readUint16Be());
}

void serializeCookieEchoChunk(MemoryOutputStream& stream, const SctpCookieEchoChunk* cookieChunk) {
    stream.writeByte(cookieChunk->getSctpChunkType());
    stream.writeByte(0);
    uint16_t length = cookieChunk->getByteLength();
    stream.writeUint16Be(length);
    stream.writeByteRepeatedly(0, length - 4);
    //ASSERT(cookieChunk->getByteLength() - 4 == cookieChunk->getCookieArraySize());
    //for (uint32_t i = 0; i < cookieChunk->getCookieArraySize(); ++i)
    //    stream.writeByte(cookieChunk->getCookie(i));

    // TODO, FIXME: do somethingt with this local tie tag...
    /*

stream.writeUint16Be(cookieChunk->getByteLength());
-    uint32_t cookielen = cookieChunk->getCookieArraySize();
-    if (cookielen > 0) {
-        for (uint32_t i = 0; i < cookielen; ++i)
-            stream.writeByte(cookieChunk->getCookie(i));
-    }
-    else {
-        SctpCookie *stateCookie = (SctpCookie *)(cookieChunk->getStateCookie());
-        stream.writeUint32Be(stateCookie->getCreationTime().inUnit(SIMTIME_MS));    // FIXME: ms?
-        stream.writeUint32Be(stateCookie->getLocalTag());
-        stream.writeUint32Be(stateCookie->getPeerTag());
-        for (uint32_t i = 0; i < 32; ++i) {
-            stream.writeByte(stateCookie->getLocalTieTag(i));
-        }
-        for (uint32_t i = 0; i < 32; ++i) {
-            stream.writeByte(stateCookie->getPeerTieTag(i));
-        }
-    }
-    uint32 uLen = cookieChunk->getUnrecognizedParametersArraySize();
-    if (uLen > 0) {
-        // FIXME
-        stream.writeByte(ERRORTYPE);
-        stream.writeByte(0);
-        stream.writeByte(uLen + 8);
-        stream.writeByte(UNRECOGNIZED_PARAMETER);
-        stream.writeByte(0);
-        stream.writeByte(uLen + 4);
-        for (uint32_t i = 0; i < uLen; ++i) {
-            stream.writeByte(cookieChunk->getUnrecognizedParameters(i));
-        }
-    }


    */
}

void deserializeCookieEchoChunk(MemoryInputStream& stream, SctpCookieEchoChunk *cookieChunk) {
    cookieChunk->setSctpChunkType(COOKIE_ECHO);
    stream.readByte();
    uint16_t length = stream.readUint16Be();
    cookieChunk->setByteLength(length);
    //cookieChunk->setCookieArraySize(length - 4);
    //for (uint32_t i = 0; i < length - 4; ++i)
    //    cookieChunk->setCookie(i, stream.readByte());
    SctpCookie *stateCookie = new SctpCookie();
    stateCookie->setLength(length - 4);
    stream.readByteRepeatedly(0, length - 4);
    cookieChunk->setStateCookie(stateCookie);
}

void serializeCookieAckChunk(MemoryOutputStream& stream, const SctpCookieAckChunk* cookieAckChunk) {
    stream.writeByte(cookieAckChunk->getSctpChunkType());
    stream.writeByte(0);
    ASSERT(cookieAckChunk->getByteLength() == 4);
    stream.writeUint16Be(cookieAckChunk->getByteLength());
}

void deserializeCookieAckChunk(MemoryInputStream& stream, SctpCookieAckChunk *cookieAckChunk) {
    cookieAckChunk->setSctpChunkType(COOKIE_ACK);
    stream.readByte();
    uint16_t length = stream.readUint16Be();
    // TODO: check whether it is 4 or not
    cookieAckChunk->setByteLength(length);  // must be 4
}

void serializeShutdownCompleteChunk(MemoryOutputStream& stream, const SctpShutdownCompleteChunk* shutdownCompleteChunk) {
    stream.writeByte(shutdownCompleteChunk->getSctpChunkType());
    stream.writeNBitsOfUint64Be(0, 7);
    stream.writeBit(shutdownCompleteChunk->getTBit());
    stream.writeUint16Be(shutdownCompleteChunk->getByteLength());  // must be 4
}

void deserializeShutdownCompleteChunk(MemoryInputStream& stream, SctpShutdownCompleteChunk *shutdownCompleteChunk) {
    shutdownCompleteChunk->setSctpChunkType(SHUTDOWN_COMPLETE);
    stream.readNBitsToUint64Be(7);
    shutdownCompleteChunk->setTBit(stream.readBit());
    shutdownCompleteChunk->setByteLength(stream.readUint16Be());  // must be 4
}

void serializeAuthenticationChunk(MemoryOutputStream& stream, const SctpAuthenticationChunk* authChunk) {
    stream.writeByte(authChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(SCTP_AUTH_CHUNK_LENGTH + SHA_LENGTH);
    stream.writeUint16Be(authChunk->getSharedKey());
    stream.writeUint16Be(authChunk->getHMacIdentifier());
    for (uint8_t i = 0; i < SHA_LENGTH; ++i) {
        stream.writeByte(0);
    }
}

void deserializeAuthenticationChunk(MemoryInputStream& stream, SctpAuthenticationChunk *authChunk) {
    authChunk->setSctpChunkType(AUTH);
    stream.readByte();
    uint16_t len = stream.readUint16Be();
    authChunk->setByteLength(len);
    authChunk->setSharedKey(stream.readUint16Be());
    authChunk->setHMacIdentifier(stream.readUint16Be());
    for (uint8_t i = 0; i < len - SCTP_AUTH_CHUNK_LENGTH; ++i) {
        stream.readByte();
    }
}

void serializeForwardTsnChunk(MemoryOutputStream& stream, const SctpForwardTsnChunk* forward) {
    stream.writeByte(forward->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(forward->getByteLength());
    stream.writeUint32Be(forward->getNewCumTsn());
    ASSERT(forward->getSidArraySize() == forward->getSsnArraySize());
    for (uint32_t i = 0; i < forward->getSidArraySize(); ++i) {
        stream.writeUint16Be(forward->getSid(i));
        stream.writeUint16Be(forward->getSsn(i));
    }
}

void deserializeForwardTsnChunk(MemoryInputStream& stream, SctpForwardTsnChunk *forward) {
    forward->setSctpChunkType(FORWARD_TSN);
    stream.readByte();
    forward->setByteLength(stream.readUint16Be());
    forward->setNewCumTsn(stream.readUint32Be());
    uint32_t num = (forward->getByteLength() - 8) / 4;
    forward->setSidArraySize(num);
    forward->setSsnArraySize(num);
    for (uint32_t i = 0; i < num; ++i) {
        forward->setSid(i, stream.readUint16Be());
        forward->setSsn(i, stream.readUint16Be());
    }
}

void serializeAsconfChangeChunk(MemoryOutputStream& stream, const SctpAsconfChunk* asconfChunk) {
    stream.writeByte(asconfChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(asconfChunk->getByteLength());
    stream.writeUint32Be(asconfChunk->getSerialNumber());

    stream.writeByte(INIT_PARAM_IPV4);
    stream.writeByte(0);
    stream.writeUint16Be(8);
    stream.writeIpv4Address(asconfChunk->getAddressParam().toIpv4());

    for (uint32_t i = 0; i < asconfChunk->getAsconfParamsArraySize(); ++i) {
        SctpParameter *parameter = (SctpParameter *)(asconfChunk->getAsconfParams(i));
        switch (parameter->getParameterType()) {
            case ADD_IP_ADDRESS: {
                SctpAddIPParameter *addip = check_and_cast<SctpAddIPParameter *>(parameter);
                stream.writeUint16Be(ADD_IP_ADDRESS);
                stream.writeUint16Be(addip->getByteLength());
                stream.writeUint32Be(addip->getRequestCorrelationId());
                stream.writeByte(INIT_PARAM_IPV4);
                stream.writeByte(8);
                stream.writeIpv4Address(addip->getAddressParam().toIpv4());
                break;
            }
            case DELETE_IP_ADDRESS: {
                SctpDeleteIPParameter *deleteip = check_and_cast<SctpDeleteIPParameter *>(parameter);
                stream.writeUint16Be(DELETE_IP_ADDRESS);
                stream.writeUint16Be(deleteip->getByteLength());
                stream.writeUint32Be(deleteip->getRequestCorrelationId());
                stream.writeByte(INIT_PARAM_IPV4);
                stream.writeByte(8);
                stream.writeIpv4Address(deleteip->getAddressParam().toIpv4());
                break;
            }
            case SET_PRIMARY_ADDRESS: {
                SctpSetPrimaryIPParameter *setip = check_and_cast<SctpSetPrimaryIPParameter *>(parameter);
                stream.writeUint16Be(SET_PRIMARY_ADDRESS);
                stream.writeUint16Be(setip->getByteLength());
                stream.writeUint32Be(setip->getRequestCorrelationId());
                stream.writeByte(INIT_PARAM_IPV4);
                stream.writeByte(8);
                stream.writeIpv4Address(setip->getAddressParam().toIpv4());
                break;
            }
            default:
                throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
        }
    }
}

void deserializeAsconfChangeChunk(MemoryInputStream& stream, SctpAsconfChunk *asconfChunk) {
    asconfChunk->setSctpChunkType(ASCONF);
    stream.readByte();
    asconfChunk->setByteLength(stream.readUint16Be());
    asconfChunk->setSerialNumber(stream.readUint32Be());

    stream.readByte();
    stream.readByte();
    stream.readUint16Be();
    asconfChunk->setAddressParam(stream.readIpv4Address());

    uint8_t arrsize = (asconfChunk->getByteLength() - 16) / 12;
    asconfChunk->setAsconfParamsArraySize(arrsize);
    for (uint32_t i = 0; i < arrsize; ++i) {
        uint16_t type = stream.readUint16Be();
        switch (type) {
            case ADD_IP_ADDRESS: {
                SctpAddIPParameter *addip = new SctpAddIPParameter();
                stream.readUint16Be();
                addip->setRequestCorrelationId(stream.readUint32Be());
                stream.readByte();
                stream.readByte();
                addip->setAddressParam(stream.readIpv4Address());
                asconfChunk->setAsconfParams(i, addip);
                break;
            }
            case DELETE_IP_ADDRESS: {
                SctpDeleteIPParameter *deleteip = new SctpDeleteIPParameter();
                stream.readUint16Be();
                deleteip->setRequestCorrelationId(stream.readUint32Be());
                stream.readByte();
                stream.readByte();
                deleteip->setAddressParam(stream.readIpv4Address());
                asconfChunk->setAsconfParams(i, deleteip);
                break;
            }
            case SET_PRIMARY_ADDRESS: {
                SctpSetPrimaryIPParameter *setip = new SctpSetPrimaryIPParameter();
                stream.readUint16Be();
                setip->setRequestCorrelationId(stream.readUint32Be());
                stream.readByte();
                stream.readByte();
                setip->setAddressParam(stream.readIpv4Address());
                asconfChunk->setAsconfParams(i, setip);
                break;
            }
            default:
                throw cRuntimeError("Parameter Type %d not supported", type);
        }
    }
}

void serializeAsconfAckChunk(MemoryOutputStream& stream, const SctpAsconfAckChunk* asconfAckChunk) {
    stream.writeByte(asconfAckChunk->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(asconfAckChunk->getByteLength());
    stream.writeUint32Be(asconfAckChunk->getSerialNumber());

    for (uint32_t i = 0; i < asconfAckChunk->getAsconfResponseArraySize(); ++i) {
        SctpParameter *parameter = check_and_cast<SctpParameter *>(asconfAckChunk->getAsconfResponse(i));
        switch (parameter->getParameterType()) {
            case ERROR_CAUSE_INDICATION: {
                SctpErrorCauseParameter *error = check_and_cast<SctpErrorCauseParameter *>(parameter);
                stream.writeByte(error->getParameterType());
                stream.writeByte(error->getByteLength());
                stream.writeUint32Be(error->getResponseCorrelationId());

                if (check_and_cast<SctpParameter *>(error->getEncapsulatedPacket()) != nullptr) {
                    SctpParameter *encParameter = check_and_cast<SctpParameter *>(error->getEncapsulatedPacket());
                    switch (encParameter->getParameterType()) {
                        case ADD_IP_ADDRESS: {
                            SctpAddIPParameter *addip = check_and_cast<SctpAddIPParameter *>(encParameter);
                            stream.writeByte(ADD_IP_ADDRESS);
                            stream.writeByte(addip->getByteLength());
                            stream.writeUint32Be(addip->getRequestCorrelationId());
                            stream.writeByte(INIT_PARAM_IPV4);
                            stream.writeByte(8);
                            stream.writeIpv4Address(addip->getAddressParam().toIpv4());
                            break;
                        }
                        case DELETE_IP_ADDRESS: {
                            SctpDeleteIPParameter *deleteip = check_and_cast<SctpDeleteIPParameter *>(encParameter);
                            stream.writeByte(DELETE_IP_ADDRESS);
                            stream.writeByte(deleteip->getByteLength());
                            stream.writeUint32Be(deleteip->getRequestCorrelationId());
                            stream.writeByte(INIT_PARAM_IPV4);
                            stream.writeByte(8);
                            stream.writeIpv4Address(deleteip->getAddressParam().toIpv4());
                            break;
                        }
                        case SET_PRIMARY_ADDRESS: {
                            SctpSetPrimaryIPParameter *setip = check_and_cast<SctpSetPrimaryIPParameter *>(encParameter);
                            stream.writeByte(SET_PRIMARY_ADDRESS);
                            stream.writeByte(setip->getByteLength());
                            stream.writeUint32Be(setip->getRequestCorrelationId());
                            stream.writeByte(INIT_PARAM_IPV4);
                            stream.writeByte(8);
                            stream.writeIpv4Address(setip->getAddressParam().toIpv4());
                            break;
                        }
                        throw cRuntimeError("Parameter Type %d not supported", encParameter->getParameterType());
                    }
                }
                break;
            }
            case SUCCESS_INDICATION: {
                SctpSuccessIndication *success = check_and_cast<SctpSuccessIndication *>(parameter);
                stream.writeByte(success->getParameterType());
                stream.writeByte(8);
                stream.writeUint32Be(success->getResponseCorrelationId());
                break;
            }
            default:
                throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
        }
    }
}

void deserializeAsconfAckChunk(MemoryInputStream& stream, SctpAsconfAckChunk *asconfAckChunk) {
    asconfAckChunk->setSctpChunkType(ASCONF_ACK);
    stream.readByte();
    asconfAckChunk->setByteLength(stream.readUint16Be());
    asconfAckChunk->setSerialNumber(stream.readUint32Be());

    uint32_t bytes_to_read = asconfAckChunk->getByteLength() - 8;
    while (bytes_to_read > 0) {
        uint8_t type = stream.readByte();
        switch (type) {
            case ERROR_CAUSE_INDICATION: {
                SctpErrorCauseParameter *error = new SctpErrorCauseParameter("ERROR_CAUSE");
                error->setParameterType(stream.readByte());
                error->setByteLength(stream.readByte());
                error->setResponseCorrelationId(stream.readUint32Be());
                uint8_t paramType = stream.readByte();
                //chunk->encapsulate(smsg);
                switch (paramType) {
                    case ADD_IP_ADDRESS: {
                        SctpAddIPParameter *addip = new SctpAddIPParameter();
                        stream.readByte();
                        addip->setByteLength(stream.readByte());
                        addip->setRequestCorrelationId(stream.readUint32Be());
                        stream.readByte();
                        stream.readByte();
                        addip->setAddressParam(stream.readIpv4Address());
                        error->encapsulate(addip);
                        break;
                    }
                    case DELETE_IP_ADDRESS: {
                        SctpDeleteIPParameter *deleteip = new SctpDeleteIPParameter();
                        stream.readByte();
                        deleteip->setByteLength(stream.readByte());
                        deleteip->setRequestCorrelationId(stream.readUint32Be());
                        stream.readByte();
                        stream.readByte();
                        deleteip->setAddressParam(stream.readIpv4Address());
                        error->encapsulate(deleteip);
                        break;
                    }
                    case SET_PRIMARY_ADDRESS: {
                        SctpSetPrimaryIPParameter *setip = new SctpSetPrimaryIPParameter();
                        stream.readByte();
                        setip->setByteLength(stream.readByte());
                        setip->setRequestCorrelationId(stream.readUint32Be());
                        stream.readByte();
                        stream.readByte();
                        setip->setAddressParam(stream.readIpv4Address());
                        error->encapsulate(setip);
                        break;
                    }
                }
                asconfAckChunk->addAsconfResponse(error);
                break;
            }
            case SUCCESS_INDICATION: {
                SctpSuccessIndication *success = new SctpSuccessIndication();
                success->setParameterType(stream.readByte());
                stream.readByte();
                success->setResponseCorrelationId(stream.readUint32Be());
                break;
            }
            default: {
                stream.readByteRepeatedly(0, bytes_to_read);
                break;
            }
        }
    }
}

void serializeErrorChunk(MemoryOutputStream& stream, const SctpErrorChunk* errorchunk) {
    stream.writeByte(errorchunk->getSctpChunkType());
    stream.writeNBitsOfUint64Be(0, 6);
    stream.writeBit(errorchunk->getMBit());
    stream.writeBit(errorchunk->getTBit());
    stream.writeUint16Be(errorchunk->getByteLength());
    if (errorchunk->getParametersArraySize() > 0) {
        SctpParameter *parameter = check_and_cast<SctpParameter *>(errorchunk->getParameters(0));
        switch (parameter->getParameterType()) {
            case MISSING_NAT_ENTRY: {
                SctpSimpleErrorCauseParameter *ecp = check_and_cast<SctpSimpleErrorCauseParameter *>(parameter);
                stream.writeUint16Be(ecp->getParameterType());
                stream.writeUint16Be(ecp->getByteLength());
                stream.writeByteRepeatedly(ecp->getValue(), ecp->getByteLength() - 4);
                break;
            }
            case INVALID_STREAM_IDENTIFIER: {
                SctpSimpleErrorCauseParameter *ecp = check_and_cast<SctpSimpleErrorCauseParameter *>(parameter);
                stream.writeUint16Be(ecp->getParameterType());
                stream.writeUint16Be(ecp->getByteLength());
                stream.writeUint16Be(ecp->getValue());
                stream.writeUint16Be(0);
                break;
            }
            default:
                throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
        }
    }
}

void deserializeErrorChunk(MemoryInputStream& stream, SctpErrorChunk *errorchunk) {
    errorchunk->setSctpChunkType(ERRORTYPE);
    stream.readNBitsToUint64Be(6);
    errorchunk->setMBit(stream.readBit());
    errorchunk->setTBit(stream.readBit());
    errorchunk->setByteLength(stream.readUint16Be());
    if (errorchunk->getByteLength() > 4) {
        errorchunk->setParametersArraySize(1);
        uint8_t type = stream.readByte();
        switch (type) {
            case MISSING_NAT_ENTRY: {
                SctpSimpleErrorCauseParameter *ecp = new SctpSimpleErrorCauseParameter();
                ecp->setParameterType(MISSING_NAT_ENTRY);
                ecp->setByteLength(stream.readUint16Be());
                ecp->setValue(stream.readByteRepeatedly(0, ecp->getByteLength() - 4));
                break;
            }
            case INVALID_STREAM_IDENTIFIER: {
                SctpSimpleErrorCauseParameter *ecp = new SctpSimpleErrorCauseParameter();
                ecp->setParameterType(INVALID_STREAM_IDENTIFIER);
                ecp->setByteLength(stream.readUint16Be());
                ecp->setValue(stream.readUint16Be());
                stream.readUint16Be();
                break;
            }
            default:
                break;
        }
    }
}

void serializeReConfigurationChunk(MemoryOutputStream& stream, const SctpStreamResetChunk* streamReset) {
    stream.writeByte(streamReset->getSctpChunkType());
    stream.writeByte(0);
    stream.writeUint16Be(streamReset->getByteLength());
    uint16_t numParameters = streamReset->getParametersArraySize();
    for (uint16_t i = 0; i < numParameters; ++i) {
        SctpParameter *parameter = (SctpParameter *)(streamReset->getParameters(i));
        switch (parameter->getParameterType()) {
            case OUTGOING_RESET_REQUEST_PARAMETER: {
                SctpOutgoingSsnResetRequestParameter *outparam = check_and_cast<SctpOutgoingSsnResetRequestParameter *>(parameter);
                stream.writeUint16Be(outparam->getParameterType());
                stream.writeUint16Be(16 + 2 * outparam->getStreamNumbersArraySize());
                stream.writeUint32Be(outparam->getSrReqSn());
                stream.writeUint32Be(outparam->getSrResSn());
                stream.writeUint32Be(outparam->getLastTsn());
                for (uint32_t i = 0; i < outparam->getStreamNumbersArraySize(); ++i) {
                    stream.writeUint16Be(outparam->getStreamNumbers(i));
                }
                break;
            }
            case INCOMING_RESET_REQUEST_PARAMETER: {
                SctpIncomingSsnResetRequestParameter *inparam = check_and_cast<SctpIncomingSsnResetRequestParameter *>(parameter);
                stream.writeUint16Be(inparam->getParameterType());
                stream.writeUint16Be(8 + 2 * inparam->getStreamNumbersArraySize());
                stream.writeUint32Be(inparam->getSrReqSn());
                for (uint32_t i = 0; i < inparam->getStreamNumbersArraySize(); ++i) {
                    stream.writeUint16Be(inparam->getStreamNumbers(i));
                }
                break;
            }
            case SSN_TSN_RESET_REQUEST_PARAMETER: {
                SctpSsnTsnResetRequestParameter *ssnparam = check_and_cast<SctpSsnTsnResetRequestParameter *>(parameter);
                stream.writeUint16Be(ssnparam->getParameterType());
                stream.writeUint16Be(8);
                stream.writeUint32Be(ssnparam->getSrReqSn());
                break;
            }
            case STREAM_RESET_RESPONSE_PARAMETER: {
                SctpStreamResetResponseParameter *response = check_and_cast<SctpStreamResetResponseParameter *>(parameter);
                stream.writeUint16Be(response->getParameterType());
                if (response->getSendersNextTsn() != 0)
                    stream.writeUint16Be(20);
                else
                    stream.writeUint16Be(12);
                stream.writeUint32Be(response->getSrResSn());
                stream.writeUint32Be(response->getResult());
                if (response->getSendersNextTsn() != 0) {
                    stream.writeUint32Be(response->getSendersNextTsn());
                    stream.writeUint32Be(response->getReceiversNextTsn());
                }
                break;
            }
            case ADD_OUTGOING_STREAMS_REQUEST_PARAMETER: {
                SctpAddStreamsRequestParameter *outstreams = check_and_cast<SctpAddStreamsRequestParameter *>(parameter);
                stream.writeUint16Be(outstreams->getParameterType());
                stream.writeUint16Be(12);
                stream.writeUint32Be(outstreams->getSrReqSn());
                stream.writeUint16Be(outstreams->getNumberOfStreams());
                stream.writeUint16Be(0);
                break;
            }
            case ADD_INCOMING_STREAMS_REQUEST_PARAMETER: {
                SctpAddStreamsRequestParameter *instreams = check_and_cast<SctpAddStreamsRequestParameter *>(parameter);
                stream.writeUint16Be(instreams->getParameterType());
                stream.writeUint16Be(12);
                stream.writeUint32Be(instreams->getSrReqSn());
                stream.writeUint16Be(instreams->getNumberOfStreams());
                stream.writeUint16Be(0);
                break;
            }
            default:
                throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
        }
    }
}

}

void SctpHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    b startPos = stream.getLength();
    //std::cout << "initial length of stream (serialize): " << stream.getLength().get() << endl;
    const auto& sctpHeader = staticPtrCast<const SctpHeader>(chunk);

    stream.writeUint16Be(sctpHeader->getSourcePort());
    stream.writeUint16Be(sctpHeader->getDestPort());
    stream.writeUint32Be(sctpHeader->getVTag());
    stream.writeUint32Be(sctpHeader->getCrc());

    // SCTP chunks:
    int32 numChunks = sctpHeader->getSctpChunksArraySize();
    //stream.writeUint32Be(numChunks);
    for (int32 cc = 0; cc < numChunks; cc++) {
        SctpChunk *chunk = const_cast<SctpChunk *>(check_and_cast<const SctpChunk *>((sctpHeader)->getSctpChunks(cc)));
        unsigned char chunkType = chunk->getSctpChunkType();
        switch (chunkType) {
            case DATA: {
                SctpDataChunk *dataChunk = check_and_cast<SctpDataChunk *>(chunk);
                //std::cout << "serialize data chunk" << endl;
                //std::cout << "chunkLength of this chunk: " << (sctpHeader->getChunkLength() - B(16)).str().c_str() << endl;
                //std::cout << "stream before: " << stream.getLength().str().c_str() << endl;
                serializeDataChunk(stream, dataChunk);
                //std::cout << "stream after: " << stream.getLength().str().c_str() << endl;
                break;
            }
            case INIT: {
                SctpInitChunk *initChunk = check_and_cast<SctpInitChunk *>(chunk);
                //std::cout << "serialize init chunk" << endl;
                serializeInitChunk(stream, initChunk);
                break;
            }
            case INIT_ACK: {
                SctpInitAckChunk *initAckChunk = check_and_cast<SctpInitAckChunk *>(chunk);
                //std::cout << "serialize init ack chunk" << endl;
                serializeInitAckChunk(stream, initAckChunk);
                break;
            }
            case SACK: {
                SctpSackChunk *sackChunk = check_and_cast<SctpSackChunk *>(chunk);
                //std::cout << "serialize sack chunk" << endl;
                serializeSackChunk(stream, sackChunk);
                break;
            }
            case NR_SACK: {
                SctpSackChunk *sackChunk = check_and_cast<SctpSackChunk *>(chunk);
                //std::cout << "serialize nrsack chunk" << endl;
                serializeNrSackChunk(stream, sackChunk);
                break;
            }
            case HEARTBEAT : {
                SctpHeartbeatChunk *heartbeatChunk = check_and_cast<SctpHeartbeatChunk *>(chunk);
                //std::cout << "serialize heartbeat chunk" << endl;
                serializeHeartbeatChunk(stream, heartbeatChunk);
                break;
            }
            case HEARTBEAT_ACK : {
                SctpHeartbeatAckChunk *heartbeatAckChunk = check_and_cast<SctpHeartbeatAckChunk *>(chunk);
                //std::cout << "serialize heartbeat ack chunk" << endl;
                serializeHeartbeatAckChunk(stream, heartbeatAckChunk);
                break;
            }
            case ABORT: {
                SctpAbortChunk *abortChunk = check_and_cast<SctpAbortChunk *>(chunk);
                //std::cout << "serialize abort chunk" << endl;
                serializeAbortChunk(stream, abortChunk);
                break;
            }
            case COOKIE_ECHO: {
                SctpCookieEchoChunk *cookieChunk = check_and_cast<SctpCookieEchoChunk *>(chunk);
                //std::cout << "serialize cookie echo chunk" << endl;
                serializeCookieEchoChunk(stream, cookieChunk);
                break;
            }
            case COOKIE_ACK: {
                SctpCookieAckChunk *cookieAckChunk = check_and_cast<SctpCookieAckChunk *>(chunk);
                //std::cout << "serialize cookie ack chunk" << endl;
                serializeCookieAckChunk(stream, cookieAckChunk);
                break;
            }
            case SHUTDOWN: {
                SctpShutdownChunk *shutdownChunk = check_and_cast<SctpShutdownChunk *>(chunk);
                //std::cout << "serialize shutdown chunk" << endl;
                serializeShutdownChunk(stream, shutdownChunk);
                break;
            }
            case SHUTDOWN_ACK: {
                SctpShutdownAckChunk *shutdownAckChunk = check_and_cast<SctpShutdownAckChunk *>(chunk);
                //std::cout << "serialize shutdown ack chunk" << endl;
                serializeShutdownAckChunk(stream, shutdownAckChunk);
                break;
            }
            case SHUTDOWN_COMPLETE: {
                SctpShutdownCompleteChunk *shutdownCompleteChunk = check_and_cast<SctpShutdownCompleteChunk *>(chunk);
                //std::cout << "serialize shutdown complete chunk" << endl;
                serializeShutdownCompleteChunk(stream, shutdownCompleteChunk);
                break;
            }
            case AUTH: {
                SctpAuthenticationChunk *authChunk = check_and_cast<SctpAuthenticationChunk *>(chunk);
                //std::cout << "serialize auth chunk" << endl;
                serializeAuthenticationChunk(stream, authChunk);
                break;
            }
            case FORWARD_TSN: {
                SctpForwardTsnChunk *forward = check_and_cast<SctpForwardTsnChunk *>(chunk);
                //std::cout << "serialize forward tsn chunk" << endl;
                serializeForwardTsnChunk(stream, forward);
                break;
            }
            case ASCONF: {
                SctpAsconfChunk *asconfChunk = check_and_cast<SctpAsconfChunk *>(chunk);
                //std::cout << "serialize asconf chunk" << endl;
                serializeAsconfChangeChunk(stream, asconfChunk);
                break;
            }
            case ASCONF_ACK: {
                SctpAsconfAckChunk *asconfAckChunk = check_and_cast<SctpAsconfAckChunk *>(chunk);
                //std::cout << "serialize asconf ack chunk" << endl;
                serializeAsconfAckChunk(stream, asconfAckChunk);
                break;
            }
            case ERRORTYPE: {
                SctpErrorChunk *errorchunk = check_and_cast<SctpErrorChunk *>(chunk);
                //std::cout << "serialize error type chunk" << endl;
                serializeErrorChunk(stream, errorchunk);
                break;
            }
            case RE_CONFIG: {
                SctpStreamResetChunk *streamReset = check_and_cast<SctpStreamResetChunk *>(chunk);
                //std::cout << "serialize reconfig chunk" << endl;
                serializeReConfigurationChunk(stream, streamReset);
                break;
            }
            //case PKTDROP: {
                //SctpPacketDropChunk *packetdrop = check_and_cast<SctpPacketDropChunk *>(chunk);
                //std::cout << "serialize packet drop chunk" << endl;
                // TODO
            //    break;
            //}
            default:
                throw new cRuntimeError("Unknown chunk type %d in outgoing packet on external interface!", chunkType);
        }
    }
    //int remaining = b(sctpHeader->getChunkLength() - (stream.getLength() - startPos)).get();
    //if (remaining > 0)
    //    stream.writeBitRepeatedly(false, remaining);
    std::cout << "final length of stream (serialize): " << (stream.getLength() - startPos).str().c_str() << endl;
}

const Ptr<Chunk> SctpHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    std::cout << "initial length of stream (deserialize): " << stream.getRemainingLength().str().c_str() << endl;
    auto sctpHeader = makeShared<SctpHeader>();
    sctpHeader->setSourcePort(stream.readUint16Be());
    sctpHeader->setDestPort(stream.readUint16Be());
    sctpHeader->setVTag(stream.readUint32Be());
    sctpHeader->setCrc(stream.readUint32Be());


    //int32_t numChunks = stream.readUint32Be();
    //sctpHeader->setSctpChunksArraySize(numChunks);
    // catch ALL chunks - when a chunk is taken, the chunkPtr is set to the next chunk
    //for (int32_t cc = 0; cc < numChunks; cc++) {
    while (stream.getRemainingLength() > B(0)) {
        int8_t chunkType = stream.readByte();
        switch (chunkType) {
            case DATA: {
                SctpDataChunk *dataChunk = new SctpDataChunk("DATA");
                //std::cout << "deserialize data chunk" << endl;
                //std::cout << "stream before: " << stream.getRemainingLength().str().c_str() << endl;
                deserializeDataChunk(stream, dataChunk);
                //std::cout << "stream after: " << stream.getRemainingLength().str().c_str() << endl;
                sctpHeader->insertSctpChunks(dataChunk);
                break;
            }
            case INIT: {
                SctpInitChunk *initChunk = new SctpInitChunk("INIT");
                //std::cout << "deserialize init chunk" << endl;
                deserializeInitChunk(stream, initChunk);
                sctpHeader->insertSctpChunks(initChunk);
                break;
            }
            case INIT_ACK: {
                SctpInitAckChunk *initAckChunk = new SctpInitAckChunk("INIT_ACK");
                //std::cout << "deserialize init ack chunk" << endl;
                deserializeInitAckChunk(stream, initAckChunk);
                sctpHeader->insertSctpChunks(initAckChunk);
                break;
            }
            case SACK: {
                SctpSackChunk *sackChunk = new SctpSackChunk("SACK");
                //std::cout << "deserialize sack chunk" << endl;
                deserializeSackChunk(stream, sackChunk);
                sctpHeader->insertSctpChunks(sackChunk);
                break;
            }
            case NR_SACK: {
                SctpSackChunk *sackChunk = new SctpSackChunk("NR_SACK");
                //std::cout << "deserialize nr sack chunk" << endl;
                deserializeNrSackChunk(stream, sackChunk);
                sctpHeader->insertSctpChunks(sackChunk);
                break;
            }
            case HEARTBEAT: {
                SctpHeartbeatChunk *heartbeatChunk = new SctpHeartbeatChunk("HEARTBEAT");
                //std::cout << "deserialize heartbeat chunk" << endl;
                deserializeHeartbeatChunk(stream, heartbeatChunk);
                sctpHeader->insertSctpChunks(heartbeatChunk);
                break;
            }
            case HEARTBEAT_ACK: {
                SctpHeartbeatAckChunk *heartbeatAckChunk = new SctpHeartbeatAckChunk("HEARTBEAT_ACK");
                //std::cout << "deserialize heartbeat ack chunk" << endl;
                deserializeHeartbeatAckChunk(stream, heartbeatAckChunk);
                sctpHeader->insertSctpChunks(heartbeatAckChunk);
                break;
            }
            case ABORT: {
                SctpAbortChunk *abortChunk = new SctpAbortChunk("ABORT");
                //std::cout << "deserialize abort chunk" << endl;
                deserializeAbortChunk(stream, abortChunk);
                sctpHeader->insertSctpChunks(abortChunk);
                break;
            }
            case COOKIE_ECHO: {
                SctpCookieEchoChunk *cookieChunk = new SctpCookieEchoChunk("COOKIE_ECHO");
                //std::cout << "deserialize cookie echo chunk" << endl;
                deserializeCookieEchoChunk(stream, cookieChunk);
                sctpHeader->insertSctpChunks(cookieChunk);
                break;
            }
            case COOKIE_ACK: {
                SctpCookieAckChunk *cookieAckChunk = new SctpCookieAckChunk("COOKIE_ACK");
                //std::cout << "deserialize cookie ack chunk" << endl;
                deserializeCookieAckChunk(stream, cookieAckChunk);
                sctpHeader->insertSctpChunks(cookieAckChunk);
                break;
            }
            case SHUTDOWN: {
                SctpShutdownChunk *shutdownChunk = new SctpShutdownChunk("SHUTDOWN");
                //std::cout << "deserialize shutdown chunk" << endl;
                deserializeShutdownChunk(stream, shutdownChunk);
                sctpHeader->insertSctpChunks(shutdownChunk);
                break;
            }
            case SHUTDOWN_ACK: {
                SctpShutdownAckChunk *shutdownAckChunk = new SctpShutdownAckChunk("SHUTDOWN_ACK");
                //std::cout << "deserialize shutdown ack chunk" << endl;
                deserializeShutdownAckChunk(stream, shutdownAckChunk);
                sctpHeader->insertSctpChunks(shutdownAckChunk);
                break;
            }
            case SHUTDOWN_COMPLETE: {
                SctpShutdownCompleteChunk *shutdownCompleteChunk = new SctpShutdownCompleteChunk("SHUTDOWN_COMPLETE");
                //std::cout << "deserialize shutdown complete chunk" << endl;
                deserializeShutdownCompleteChunk(stream, shutdownCompleteChunk);
                sctpHeader->insertSctpChunks(shutdownCompleteChunk);
                break;
            }
            case ERRORTYPE: {
                SctpErrorChunk *errorchunk = new SctpErrorChunk("ERROR");
                //std::cout << "deserialize error chunk" << endl;
                deserializeErrorChunk(stream, errorchunk);
                sctpHeader->insertSctpChunks(errorchunk);
                break;
            }
            case FORWARD_TSN: {
                SctpForwardTsnChunk *forward = new SctpForwardTsnChunk("FORWARD_TSN");
                //std::cout << "deserialize forward tsn chunk" << endl;
                deserializeForwardTsnChunk(stream, forward);
                sctpHeader->insertSctpChunks(forward);
                break;
            }
            case AUTH: {
                SctpAuthenticationChunk *authChunk = new SctpAuthenticationChunk("AUTH");
                //std::cout << "deserialize auth chunk" << endl;
                deserializeAuthenticationChunk(stream, authChunk);
                sctpHeader->insertSctpChunks(authChunk);
                break;
            }
            case ASCONF: {
                SctpAsconfChunk *asconfChunk = new SctpAsconfChunk("ASCONF");
                //std::cout << "deserialize asconf chunk" << endl;
                deserializeAsconfChangeChunk(stream, asconfChunk);
                sctpHeader->insertSctpChunks(asconfChunk);
                break;
            }
            case ASCONF_ACK: {
                SctpAsconfAckChunk *asconfAckChunk = new SctpAsconfAckChunk("ASCONF_ACK");
                //std::cout << "deserialize asconf ack chunk" << endl;
                deserializeAsconfAckChunk(stream, asconfAckChunk);
                sctpHeader->insertSctpChunks(asconfAckChunk);
                break;
            }
            case RE_CONFIG: {
                SctpStreamResetChunk *chunk = new SctpStreamResetChunk("RE_CONFIG");
                //std::cout << "deserialize re-config chunk" << endl;
                // TODO
                break;
            }
            //case PKTDROP: {
             /*   const struct pktdrop_chunk *drop;
                drop = (struct pktdrop_chunk *)(chunks + chunkPtr);
                SctpPacketDropChunk *dropChunk;
                dropChunk = new SctpPacketDropChunk("PKTDROP");
                dropChunk->setSctpChunkType(PKTDROP);
                dropChunk->setCFlag(drop->flags & C_FLAG);
                dropChunk->setTFlag(drop->flags & T_FLAG);
                dropChunk->setBFlag(drop->flags & B_FLAG);
                dropChunk->setMFlag(drop->flags & M_FLAG);
                dropChunk->setMaxRwnd(ntohl(drop->max_rwnd));
                dropChunk->setQueuedData(ntohl(drop->queued_data));
                dropChunk->setTruncLength(ntohs(drop->trunc_length));
                EV_INFO << "SctpSerializer::pktdrop: parse SctpHeader\n";
                SctpHeader *msg;
                msg = new SctpHeader();
                parse((unsigned char *)chunks + chunkPtr + 16, bufsize - sizeof(struct common_header) - chunkPtr - 16, msg);*/
            //    break;
            //}
            default:
                EV_ERROR << "Parser: Unknown SCTP chunk type " << chunkType;
                break;
        }
    }
    //stream.readBitRepeatedly(false, b(stream.getRemainingLength()).get());
    //std::cout << "final length of stream (deserialize): " << stream.getRemainingLength().get() << endl;
    return sctpHeader;
}


} // namespace sctp

} // namespace inet
