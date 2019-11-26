//
// Copyright (C) 2008-2009 Irene Ruengeler
// Copyright (C) 2009-2012 Thomas Dreibholz
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "inet/transportlayer/sctp/SctpAssociation.h"
#include "inet/transportlayer/sctp/SctpHeader.h"

namespace inet {
namespace sctp {

Register_Class(SctpHeader);

SctpHeader& SctpHeader::operator=(const SctpHeader& other)
{
    if (this == &other)
        return *this;
    clean();
    SctpHeader_Base::operator=(other);
    copy(other);
    return *this;
}


void SctpHeader::copy(const SctpHeader& other)
{
   // handleChange();
    setVTag(other.getVTag());
    setSrcPort(other.getSrcPort());
    setDestPort(other.getDestPort());
    setChecksumOk(other.getChecksumOk());
    for (const auto & elem : other.sctpChunkList) {
        SctpChunk *chunk = (elem)->dup();
        take(chunk);
        sctpChunkList.push_back(chunk);
    }
    ASSERT(B(getChunkLength()).get() == B(other.getChunkLength()).get());
}

SctpHeader::~SctpHeader()
{
    clean();
}

void SctpHeader::clean()
{
  // handleChange();

    if (this->getSctpChunksArraySize() > 0) {
        auto iterator = sctpChunkList.begin();
        while (iterator != sctpChunkList.end()) {
           // SctpChunk *chunk = (*iterator);
            sctpChunkList.erase(iterator);
           // delete chunk;
        }
    }

   /* sctpChunkList.clear();
    setHeaderLength(SCTP_COMMON_HEADER);
    setChunkLength(B(SCTP_COMMON_HEADER));*/
}

void SctpHeader::setSctpChunksArraySize(size_t size)
{
    throw cException(this, "setSctpChunkArraySize() not supported, use insertSctpChunks()");
}

void SctpHeader::setSctpChunks(size_t k, SctpChunk *chunk)
{
    handleChange();
    SctpChunk *tmp = sctpChunkList.at(k);
    if (tmp == chunk)
        return;
    headerLength -= ADD_PADDING(tmp->getByteLength());
    dropAndDelete(tmp);
    sctpChunkList[k] = chunk;
    take(chunk);
    headerLength += ADD_PADDING(chunk->getByteLength());
    setChunkLength(B(headerLength));
}

size_t SctpHeader::getSctpChunksArraySize() const
{
    return sctpChunkList.size();
}


void SctpHeader::replaceSctpChunk(SctpChunk *chunk, uint32 k)
{
    setSctpChunks(k, chunk);
}

void SctpHeader::insertSctpChunks(SctpChunk * chunk)
{
    handleChange();
    sctpChunkList.push_back(chunk);
    take(chunk);
    headerLength += ADD_PADDING(chunk->getByteLength());
    setChunkLength(B(headerLength));
}

void SctpHeader::insertSctpChunks(size_t k, SctpChunk * chunk)
{
    handleChange();
    sctpChunkList.insert(sctpChunkList.begin()+k, chunk);
    take(chunk);
    headerLength += ADD_PADDING(chunk->getByteLength());
    setChunkLength(B(headerLength));
}

//void SctpHeader::eraseSctpChunks(size_t k)
SctpChunk *SctpHeader::removeFirstChunk()
{
    handleChange();
    if (sctpChunkList.empty())
        return nullptr;

    SctpChunk *msg = sctpChunkList.front();
    headerLength -= ADD_PADDING(msg->getByteLength());
    sctpChunkList.erase(sctpChunkList.begin());
    drop(msg);
    setChunkLength(B(headerLength));
    return msg;
}

SctpChunk *SctpHeader::removeLastChunk()
{
    handleChange();
    if (sctpChunkList.empty())
        return nullptr;

    SctpChunk *msg = sctpChunkList.back();
    sctpChunkList.pop_back();
    drop(msg);
    this->addChunkLength(B(ADD_PADDING(msg->getByteLength())));
    return msg;
}

SctpChunk *SctpHeader::peekFirstChunk() const
{
    if (sctpChunkList.empty())
        return nullptr;

    SctpChunk *msg = sctpChunkList.front();
    return msg;
}

SctpChunk *SctpHeader::peekLastChunk() const
{
    if (sctpChunkList.empty())
        return nullptr;

    SctpChunk *msg = sctpChunkList.back();
    return msg;
}

uint64_t SctpHeader::calculateChunkLength() const {
     uint64_t chunkLength = 0;

     chunkLength += 12;

     // SCTP chunks:
     int32_t numChunks = this->getSctpChunksArraySize();
     chunkLength += 4;
     for (int32_t cc = 0; cc < numChunks; cc++) {
         SctpChunk *chunk = const_cast<SctpChunk *>(check_and_cast<const SctpChunk *>((this)->getSctpChunks(cc)));
         unsigned char chunkType = chunk->getSctpChunkType();
         switch (chunkType) {
             case DATA: {
                 SctpDataChunk *dataChunk = check_and_cast<SctpDataChunk *>(chunk);
                 chunkLength += 16;
                 SctpSimpleMessage *smsg = check_and_cast<SctpSimpleMessage *>(dataChunk->getEncapsulatedPacket());
                 chunkLength += smsg->getDataLen();
                 break;
             }
             case INIT: {
                 SctpInitChunk *initChunk = check_and_cast<SctpInitChunk *>(chunk);
                 chunkLength += 20;
                 if (initChunk->getIpv4Supported() || initChunk->getIpv6Supported())
                     chunkLength += 8;
                 if (initChunk->getForwardTsn() == true)
                     chunkLength += 4;
                 for (size_t i = 0; i < initChunk->getAddressesArraySize(); ++i) {
                     if (initChunk->getAddresses(i).getType() == L3Address::IPv4)
                         chunkLength += 8;
                     else if (initChunk->getAddresses(i).getType() == L3Address::IPv6)
                         chunkLength += 20;
                 }
                 uint64_t chunkCount = initChunk->getSepChunksArraySize();
                 if (chunkCount > 0)
                     chunkLength += 4 + chunkCount;
                 uint64_t randomCount = initChunk->getRandomArraySize();
                 if (randomCount > 0)
                     chunkLength += 4 + randomCount;
                 uint64_t chunkTypeCount = initChunk->getSctpChunkTypesArraySize();
                 if (chunkTypeCount > 0)
                     chunkLength += 4 + chunkTypeCount;
                 uint64_t hmacCount = initChunk->getHmacTypesArraySize();
                 if (hmacCount > 0)
                     chunkLength += 4 + 2 * hmacCount;
                 break;
             }
             case INIT_ACK: {
                 SctpInitAckChunk *initAckChunk = check_and_cast<SctpInitAckChunk *>(chunk);
                 chunkLength += 20;
                 if (initAckChunk->getIpv4Supported() || initAckChunk->getIpv6Supported())
                     chunkLength += 8;
                 if (initAckChunk->getForwardTsn() == true)
                     chunkLength += 4;
                 for (size_t i = 0; i < initAckChunk->getAddressesArraySize(); ++i) {
                     if (initAckChunk->getAddresses(i).getType() == L3Address::IPv4)
                         chunkLength += 8;
                     else if (initAckChunk->getAddresses(i).getType() == L3Address::IPv6)
                         chunkLength += 20;
                 }
                 uint64_t chunkCount = initAckChunk->getSepChunksArraySize();
                 if (chunkCount > 0)
                     chunkLength += 4 + chunkCount;
                 uint64_t unrecognizedCount = initAckChunk->getUnrecognizedParametersArraySize();
                 if (unrecognizedCount > 0)
                     chunkLength += 4 + unrecognizedCount;
                 uint64_t randomCount = initAckChunk->getRandomArraySize();
                 if (randomCount > 0)
                     chunkLength += 4 + randomCount;
                 uint64_t chunkTypeCount = initAckChunk->getSctpChunkTypesArraySize();
                 if (chunkTypeCount > 0)
                     chunkLength += 4 + chunkTypeCount;
                 uint64_t hmacCount = initAckChunk->getHmacTypesArraySize();
                 if (hmacCount > 0)
                     chunkLength += 4 + 2 * hmacCount;
                 if (initAckChunk->getStateCookie() != nullptr)
                     chunkLength += initAckChunk->getStateCookie()->getLength();
                 break;
             }
             case SACK: {
                 SctpSackChunk *sackChunk = check_and_cast<SctpSackChunk *>(chunk);
                 chunkLength += 16;
                 chunkLength += 8;   // FIXME: there is no sack seq num in rfc4960
                 chunkLength += 8;  // FIXME: there is no dac packets received in rfc4960
                 uint16_t numgaps = sackChunk->getNumGaps();
                 chunkLength += numgaps * 4;
                 uint16_t numdups = sackChunk->getNumDupTsns();
                 chunkLength += numdups * 4;
                 break;
             }
             case NR_SACK: {
                 SctpSackChunk *sackChunk = check_and_cast<SctpSackChunk *>(chunk);
                 chunkLength += 20;
                 uint16_t numgaps = sackChunk->getNumGaps();
                 chunkLength += numgaps * 4;
                 uint16_t numnrgaps = sackChunk->getNumNrGaps();
                 chunkLength += numnrgaps * 4;
                 uint16_t numdups = sackChunk->getNumDupTsns();
                 chunkLength += numdups * 4;
                 break;
             }
             case HEARTBEAT : {
                 SctpHeartbeatChunk *heartbeatChunk = check_and_cast<SctpHeartbeatChunk *>(chunk);
                 chunkLength += 4;
                 L3Address addr = heartbeatChunk->getRemoteAddr();
                 if (addr.getType() == L3Address::IPv4)
                     chunkLength += 12;
                 if (addr.getType() == L3Address::IPv6)
                     chunkLength += 24;
                 chunkLength += 9;  // FIXME: writing simtime
                 break;
             }
             case HEARTBEAT_ACK : {
                 SctpHeartbeatAckChunk *heartbeatAckChunk = check_and_cast<SctpHeartbeatAckChunk *>(chunk);
                 chunkLength += 6;
                 uint32_t infolen = heartbeatAckChunk->getInfoArraySize();
                 if (infolen > 0)
                     chunkLength += 2 + infolen;
                 else {
                     chunkLength += 2;
                     L3Address addr = heartbeatAckChunk->getRemoteAddr();
                     if (addr.getType() == L3Address::IPv4)
                         chunkLength += 12;
                     if (addr.getType() == L3Address::IPv6)
                         chunkLength += 24;
                 }
                 chunkLength += 9;  // FIXME: writing simtime
                 break;
             }
             case ABORT: {
                 chunkLength += 4;
                 break;
             }
             case COOKIE_ECHO: {
                 SctpCookieEchoChunk *cookieChunk = check_and_cast<SctpCookieEchoChunk *>(chunk);
                 uint16_t length = cookieChunk->getByteLength();
                 chunkLength += length;
                 break;
             }
             case COOKIE_ACK: {
                 chunkLength += 4;
                 break;
             }
             case SHUTDOWN: {
                 chunkLength += 8;
                 break;
             }
             case SHUTDOWN_ACK: {
                 chunkLength += 4;
                 break;
             }
             case SHUTDOWN_COMPLETE: {
                 chunkLength += 4;
                 break;
             }
             case AUTH: {
                 chunkLength += 8 + SHA_LENGTH;
                 break;
             }
             case FORWARD_TSN: {
                 SctpForwardTsnChunk *forward = check_and_cast<SctpForwardTsnChunk *>(chunk);
                 chunkLength += 8 + forward->getSidArraySize() * 4;
                 break;
             }
             case ASCONF: {
                 SctpAsconfChunk *asconfChunk = check_and_cast<SctpAsconfChunk *>(chunk);
                 chunkLength += 16 + asconfChunk->getAsconfParamsArraySize() * 12;
                 break;
             }
             case ASCONF_ACK: {
                 SctpAsconfAckChunk *asconfAckChunk = check_and_cast<SctpAsconfAckChunk *>(chunk);
                 chunkLength += 8;
                 for (uint32_t i = 0; i < asconfAckChunk->getAsconfResponseArraySize(); ++i) {
                     SctpParameter *parameter = check_and_cast<SctpParameter *>(asconfAckChunk->getAsconfResponse(i));
                     switch (parameter->getParameterType()) {
                     case ERROR_CAUSE_INDICATION: {
                         SctpErrorCauseParameter *error = check_and_cast<SctpErrorCauseParameter *>(parameter);
                         chunkLength += 4;

                         if (check_and_cast<SctpParameter *>(error->getEncapsulatedPacket()) != nullptr) {
                             SctpParameter *encParameter = check_and_cast<SctpParameter *>(error->getEncapsulatedPacket());
                             switch (encParameter->getParameterType()) {
                             case ADD_IP_ADDRESS: {
                                 chunkLength += 12;
                                 break;
                             }
                             case DELETE_IP_ADDRESS: {
                                 chunkLength += 12;
                                 break;
                             }
                             case SET_PRIMARY_ADDRESS: {
                                 chunkLength += 12;
                                 break;
                             }
                             throw cRuntimeError("Parameter Type %d not supported", encParameter->getParameterType());
                             }
                         }
                         break;
                     }
                     case SUCCESS_INDICATION: {
                         chunkLength += 6;
                         break;
                     }
                     default:
                         throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
                     }
                 }
                 break;
             }
             case ERRORTYPE: {
                 SctpErrorChunk *errorchunk = check_and_cast<SctpErrorChunk *>(chunk);
                 chunkLength += 4;
                 if (errorchunk->getParametersArraySize() > 0) {
                     SctpParameter *parameter = check_and_cast<SctpParameter *>(errorchunk->getParameters(0));
                     switch (parameter->getParameterType()) {
                         case MISSING_NAT_ENTRY: {
                             SctpSimpleErrorCauseParameter *ecp = check_and_cast<SctpSimpleErrorCauseParameter *>(parameter);
                             chunkLength += ecp->getByteLength() - 4;
                             break;
                         }
                         case INVALID_STREAM_IDENTIFIER: {
                             chunkLength += 8;
                             break;
                         }
                         default:
                             throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
                     }
                 }
                 break;
             }
             case RE_CONFIG: {
                 SctpStreamResetChunk *streamReset = check_and_cast<SctpStreamResetChunk *>(chunk);
                 chunkLength += 4;
                 uint16_t numParameters = streamReset->getParametersArraySize();
                 for (uint16_t i = 0; i < numParameters; ++i) {
                     SctpParameter *parameter = (SctpParameter *)(streamReset->getParameters(i));
                     switch (parameter->getParameterType()) {
                         case OUTGOING_RESET_REQUEST_PARAMETER: {
                             SctpOutgoingSsnResetRequestParameter *outparam = check_and_cast<SctpOutgoingSsnResetRequestParameter *>(parameter);
                             chunkLength += 16 + outparam->getStreamNumbersArraySize() * 2;
                             break;
                         }
                         case INCOMING_RESET_REQUEST_PARAMETER: {
                             SctpIncomingSsnResetRequestParameter *inparam = check_and_cast<SctpIncomingSsnResetRequestParameter *>(parameter);
                             chunkLength += 16 + inparam->getStreamNumbersArraySize() * 2;
                             break;
                         }
                         case SSN_TSN_RESET_REQUEST_PARAMETER: {
                             chunkLength += 8;
                             break;
                         }
                         case STREAM_RESET_RESPONSE_PARAMETER: {
                             SctpStreamResetResponseParameter *response = check_and_cast<SctpStreamResetResponseParameter *>(parameter);
                             chunkLength += 12;
                             if (response->getSendersNextTsn() != 0) {
                                 chunkLength += 8;
                             }
                             break;
                         }
                         case ADD_OUTGOING_STREAMS_REQUEST_PARAMETER: {
                             chunkLength += 12;
                             break;
                         }
                         case ADD_INCOMING_STREAMS_REQUEST_PARAMETER: {
                             chunkLength += 12;
                             break;
                         }
                         default:
                             throw cRuntimeError("Parameter Type %d not supported", parameter->getParameterType());
                     }
                 }
                 break;
             }
             case PKTDROP: {
                 // TODO
                 break;
             }
             default:
                 throw new cRuntimeError("Unknown chunk type %d in outgoing packet on external interface!", chunkType);
         }
     }
     //this->setChunkLength(B(chunkLength));
     return chunkLength;
}

Register_Class(SctpErrorChunk);

SctpErrorChunk& SctpErrorChunk::operator=(const SctpErrorChunk& other)
{
    if (this == &other)
        return *this;
    clean();
    SctpErrorChunk_Base::operator=(other);
    copy(other);
    return *this;
}

void SctpErrorChunk::copy(const SctpErrorChunk& other)
{
    for (const auto & elem : other.parameterList) {
        SctpParameter *param = (elem)->dup();
        take(param);
        parameterList.push_back(param);
    }
}

void SctpErrorChunk::setParametersArraySize(size_t size)
{
    throw cException(this, "setParametersArraySize() not supported, use addParameter()");
}

size_t SctpErrorChunk::getParametersArraySize() const
{
    return parameterList.size();
}

SctpParameter * SctpErrorChunk::getParameters(size_t k) const
{
    return parameterList.at(k);
}

void SctpErrorChunk::setParameters(size_t k, SctpParameter * parameters)
{
    throw cException(this, "setParameter() not supported, use addParameter()");
}

void SctpErrorChunk::addParameters(SctpParameter *msg)
{
    take(msg);

    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    parameterList.push_back(msg);
}

SctpParameter *SctpErrorChunk::removeParameter()
{
    if (parameterList.empty())
        return nullptr;

    SctpParameter *msg = parameterList.front();
    parameterList.erase(parameterList.begin());
    drop(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    return msg;
}

SctpErrorChunk::~SctpErrorChunk()
{
    clean();
}

void SctpErrorChunk::clean()
{
    while (!parameterList.empty()) {
        cPacket *msg = parameterList.front();
        parameterList.erase(parameterList.begin());
        dropAndDelete(msg);
    }
}

Register_Class(SctpStreamResetChunk);

SctpStreamResetChunk& SctpStreamResetChunk::operator=(const SctpStreamResetChunk& other)
{
    SctpStreamResetChunk_Base::operator=(other);

    this->setByteLength(SCTP_STREAM_RESET_CHUNK_LENGTH);
    for (const auto & elem : other.parameterList)
        addParameter((elem)->dup());

    return *this;
}

void SctpStreamResetChunk::copy(const SctpStreamResetChunk& other)
{
    for (const auto & elem : other.parameterList) {
        SctpParameter *param = (elem)->dup();
        take(param);
        parameterList.push_back(param);
    }
}

void SctpStreamResetChunk::setParametersArraySize(size_t size)
{
    throw cException(this, "setParametersArraySize() not supported, use addParameter()");
}

size_t SctpStreamResetChunk::getParametersArraySize() const
{
    return parameterList.size();
}

const SctpParameter * SctpStreamResetChunk::getParameters(size_t k) const
{
    return parameterList.at(k);
}

void SctpStreamResetChunk::setParameters(size_t k, SctpParameter * parameters)
{
    throw cException(this, "setParameters() not supported, use addParameter()");
}

void SctpStreamResetChunk::addParameter(SctpParameter *msg)
{
    take(msg);
    if (this->parameterList.size() < 2) {
        this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
        parameterList.push_back(msg);
    }
    else
        throw cRuntimeError("Not more than two parameters allowed!");
}

cPacket *SctpStreamResetChunk::removeParameter()
{
    if (parameterList.empty())
        return nullptr;

    cPacket *msg = parameterList.front();
    parameterList.erase(parameterList.begin());
    drop(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    return msg;
}

SctpStreamResetChunk::~SctpStreamResetChunk()
{
    clean();
}

void SctpStreamResetChunk::clean()
{
    while (!parameterList.empty()) {
        cPacket *msg = parameterList.front();
        parameterList.erase(parameterList.begin());
        dropAndDelete(msg);
    }
}

Register_Class(SctpIncomingSsnResetRequestParameter);

void SctpIncomingSsnResetRequestParameter::copy(const SctpIncomingSsnResetRequestParameter& other)
{
    setSrReqSn(other.getSrReqSn());
    setStreamNumbersArraySize(other.getStreamNumbersArraySize());
    for (uint16 i = 0; i < other.getStreamNumbersArraySize(); i++) {
        setStreamNumbers(i, other.getStreamNumbers(i));
    }
}

Register_Class(SctpAsconfChunk);

SctpAsconfChunk& SctpAsconfChunk::operator=(const SctpAsconfChunk& other)
{
    SctpAsconfChunk_Base::operator=(other);

    this->setByteLength(SCTP_ADD_IP_CHUNK_LENGTH + 8);
    this->setAddressParam(other.getAddressParam());
    for (const auto & elem : other.parameterList)
        addAsconfParam((elem)->dup());

    return *this;
}

void SctpAsconfChunk::setAsconfParamsArraySize(size_t size)
{
    throw cException(this, "setAsconfParamsArraySize() not supported, use addAsconfParam()");
}

size_t SctpAsconfChunk::getAsconfParamsArraySize() const
{
    return parameterList.size();
}

const SctpParameter * SctpAsconfChunk::getAsconfParams(size_t k) const
{
    return parameterList.at(k);
}

void SctpAsconfChunk::setAsconfParams(size_t k, SctpParameter * asconfParams)
{
    throw cException(this, "setAsconfParams() not supported, use addAsconfParam()");
}

void SctpAsconfChunk::addAsconfParam(SctpParameter *msg)
{
    take(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    parameterList.push_back(msg);
}

SctpParameter *SctpAsconfChunk::removeAsconfParam()
{
    if (parameterList.empty())
        return nullptr;

    SctpParameter *msg = parameterList.front();
    parameterList.erase(parameterList.begin());
    drop(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    return msg;
}

Register_Class(SctpAsconfAckChunk);

SctpAsconfAckChunk& SctpAsconfAckChunk::operator=(const SctpAsconfAckChunk& other)
{
    SctpAsconfAckChunk_Base::operator=(other);

    this->setByteLength(SCTP_ADD_IP_CHUNK_LENGTH);
    for (const auto & elem : other.parameterList)
        addAsconfResponse((elem)->dup());

    return *this;
}

void SctpAsconfAckChunk::setAsconfResponseArraySize(size_t size)
{
    throw cException(this, "setAsconfResponseArraySize() not supported, use addAsconfResponse()");
}

size_t SctpAsconfAckChunk::getAsconfResponseArraySize() const
{
    return parameterList.size();
}

SctpParameter * SctpAsconfAckChunk::getAsconfResponse(size_t k) const
{
    return parameterList.at(k);
}

void SctpAsconfAckChunk::setAsconfResponse(size_t k, SctpParameter * asconfResponse)
{
    throw cException(this, "setAsconfresponse() not supported, use addAsconfResponse()");
}

void SctpAsconfAckChunk::addAsconfResponse(SctpParameter *msg)
{
    take(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    parameterList.push_back(msg);
}

SctpParameter *SctpAsconfAckChunk::removeAsconfResponse()
{
    if (parameterList.empty())
        return nullptr;

    SctpParameter *msg = parameterList.front();
    parameterList.erase(parameterList.begin());
    drop(msg);
    this->setByteLength(this->getByteLength() + ADD_PADDING(msg->getByteLength()));
    return msg;
}

} // namespace sctp
} // namespace inet

