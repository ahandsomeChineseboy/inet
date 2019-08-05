//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/linklayer/lmac/LMacHeader_m.h"
#include "inet/linklayer/lmac/LMacHeaderSerializer.h"

namespace inet {

Register_Serializer(LMacHeaderBase, LMacHeaderSerializer);
Register_Serializer(LMacControlFrame, LMacHeaderSerializer);
Register_Serializer(LMacDataFrameHeader, LMacHeaderSerializer);

void LMacHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    B startPos = B(stream.getLength());
    const auto& header = staticPtrCast<const LMacHeaderBase>(chunk);
    stream.writeByte(header->getType());
    stream.writeByte(B(header->getChunkLength()).get());
    stream.writeMacAddress(header->getSrcAddr());
    stream.writeMacAddress(header->getDestAddr());
    stream.writeUint64Be(header->getMySlot());
    uint8_t numSlots = header->getOccupiedSlotsArraySize();
    stream.writeByte(numSlots);
    uint8_t minHeaderLengthWithZeroSlots = header->getType() == LMAC_DATA ? B(stream.getLength() - startPos).get() + 2 : B(stream.getLength() - startPos).get();
    uint8_t headerLengthWithoutSlots = B(header->getChunkLength()).get() - numSlots * 6;
    int remaining = headerLengthWithoutSlots - minHeaderLengthWithZeroSlots;
    if (remaining < 0)
        throw cRuntimeError("LMacHeader length = %d smaller than required %d bytes, try to increase the 'headerLength' parameter", headerLengthWithoutSlots, minHeaderLengthWithZeroSlots);
    for (size_t i = 0; i < numSlots; ++i)
        stream.writeMacAddress(header->getOccupiedSlots(i));
    switch (header->getType()) {
        case LMAC_CONTROL: {
            break;
        }
        case LMAC_DATA: {
            const auto& dataFrame = staticPtrCast<const LMacDataFrameHeader>(chunk);
            stream.writeUint16Be(dataFrame->getNetworkProtocol());
            break;
        }
        default:
            throw cRuntimeError("Unknown header type: %d", header->getType());
    }
    while ((B(stream.getLength()) - startPos) < B(header->getChunkLength()))
            stream.writeByte('?');
}

const Ptr<Chunk> LMacHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    B startPos = stream.getPosition();
    auto header = makeShared<LMacHeaderBase>();
    LMacType type = static_cast<LMacType>(stream.readByte());
    uint8_t length = stream.readByte();
    switch (type) {
        case LMAC_CONTROL: {
            auto ctrlFrame = makeShared<LMacControlFrame>();
            ctrlFrame->setType(type);
            ctrlFrame->setChunkLength(B(length));
            ctrlFrame->setSrcAddr(stream.readMacAddress());
            ctrlFrame->setDestAddr(stream.readMacAddress());
            ctrlFrame->setMySlot(stream.readUint64Be());
            uint8_t numSlots = stream.readByte();
            ctrlFrame->setOccupiedSlotsArraySize(numSlots);
            for (size_t i = 0; i < numSlots; ++i)
                ctrlFrame->setOccupiedSlots(i, stream.readMacAddress());
            while (B(length) - (stream.getPosition() - startPos) > B(0))
                stream.readByte();
            return ctrlFrame;
        }
        case LMAC_DATA: {
            auto dataFrame = makeShared<LMacDataFrameHeader>();
            dataFrame->setType(type);
            dataFrame->setChunkLength(B(length));
            dataFrame->setSrcAddr(stream.readMacAddress());
            dataFrame->setDestAddr(stream.readMacAddress());
            dataFrame->setMySlot(stream.readUint64Be());
            uint8_t numSlots = stream.readByte();
            dataFrame->setOccupiedSlotsArraySize(numSlots);
            for (size_t i = 0; i < numSlots; ++i)
                dataFrame->setOccupiedSlots(i, stream.readMacAddress());
            dataFrame->setNetworkProtocol(stream.readUint16Be());
            while (B(length) - (stream.getPosition() - startPos) > B(0))
                stream.readByte();
            return dataFrame;
        }
        default: {
            while (B(length) - (stream.getPosition() - startPos) > B(0))
                stream.readByte();
            header->markIncorrect();
            return header;
        }
    }
}

} // namespace inet

