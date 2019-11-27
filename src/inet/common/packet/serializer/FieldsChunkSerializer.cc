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

#include "inet/common/packet/chunk/FieldsChunk.h"
#include "inet/common/packet/serializer/FieldsChunkSerializer.h"
#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/transportlayer/sctp/SctpHeader.h"

#include "inet/common/ObjectPrinter.h"
#include "inet/linklayer/ethernet/EtherFrame_m.h"
#include "inet/transportlayer/common/TransportPseudoHeader_m.h"
#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/networklayer/ted/LinkStatePacket_m.h"
#include "inet/networklayer/rsvpte/RsvpHelloMsg_m.h"
#include <fstream>
#include "inet/transportlayer/sctp/SctpHeader.h"
#include "inet/common/packet/chunk/Chunk.h"

namespace inet {
namespace {

void checkSerializer(const Ptr<const Chunk>& chunk, MemoryOutputStream& stream) {
    const Chunk *chunkPointer = chunk.get();
    if (dynamic_cast<const SliceChunk*>(chunkPointer) == nullptr && dynamic_cast<const FieldsChunk*>(chunkPointer) != nullptr &&
            dynamic_cast<const EthernetPadding*>(chunkPointer) == nullptr && dynamic_cast<const TransportPseudoHeader*>(chunkPointer) == nullptr &&
            dynamic_cast<const ApplicationPacket*>(chunkPointer) == nullptr && dynamic_cast<const LinkStateMsg*>(chunkPointer) == nullptr &&
            dynamic_cast<const RsvpHelloMsg*>(chunkPointer) == nullptr){
        ObjectPrinter p(nullptr, "*: not mutable and not className and not fullName and not fullPath and not info and not rawBin and not rawHex and not tags and not payloadProtocol and not id and not treeId and not *Tag and not creationTime and not crc and not checksumOk and not crcMode and not enqueuingTime and not firstSendTime and not sackSeqNum and not dacPacketsRcvd");
        std::string orig = p.printObjectToString(const_cast<Chunk*>(chunk.get()));

        std::vector<uint8_t> bytes;
        stream.copyData(bytes);
        MemoryInputStream tmpStream(bytes);
        const Ptr<Chunk> restoredChunk = Chunk::deserialize(tmpStream, typeid(*chunkPointer));
        std::string restored = p.printObjectToString(restoredChunk.get());

        if (orig != restored) {
            EV_STATICCONTEXT;
            EV << orig << endl;
            EV << restored << endl;
            std::ofstream one;
            one.open("/home/marcell/1");
            one << orig;
            one.close();
            std::ofstream two;
            two.open("/home/marcell/2");
            two << restored;
            two.close();
            system("meld /home/marcell/1 /home/marcell/2");
            ASSERT(false);
        }
    }
}

}


void FieldsChunkSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk, b offset, b length) const
{
    auto fieldsChunk = staticPtrCast<const FieldsChunk>(chunk);
    if (fieldsChunk->getSerializedBytes() != nullptr) {
        CHUNK_CHECK_USAGE(B(fieldsChunk->getSerializedBytes()->size()) == chunk->getChunkLength(), "serialized length is incorrect: serialized=%ld, chunk=%ld", fieldsChunk->getSerializedBytes()->size(), B(chunk->getChunkLength()).get());
        stream.writeBytes(*fieldsChunk->getSerializedBytes(), offset, length == b(-1) ? chunk->getChunkLength() - offset : length);
    }
    else if (offset == b(0) && (length == b(-1) || length == chunk->getChunkLength())) {
        auto startPosition = stream.getLength();
        serialize(stream, fieldsChunk);
        auto endPosition = stream.getLength();
        auto serializedLength = endPosition - startPosition;
        /////////////////////////////////
        std::vector<uint8_t> bytes;
        stream.copyData(bytes, startPosition, serializedLength);
        //MemoryInputStream tmpStream(bytes);
        //MemoryOutputStream chunkStream(fieldsChunk->getChunkLength());
        MemoryOutputStream chunkStream(bytes);
        checkSerializer(chunk, chunkStream);
        /////////////////////////////////
        //if (auto tmp = dynamic_cast<const inet::sctp::SctpHeader*>(chunk.get())) {
        //    if ((B(tmp->getChunkLength()).get() != tmp->calculateChunkLength()) || (tmp->calculateChunkLength() != B(serializedLength).get()))
        //        throw new cRuntimeError("actual chunkLength: %d \t supposed chunkLength: %d \t serialized length: %d", B(tmp->getChunkLength()).get(), tmp->calculateChunkLength(), B(serializedLength).get());
        //}
        ChunkSerializer::totalSerializedLength += serializedLength;
        auto serializedBytes = new std::vector<uint8_t>();
        stream.copyData(*serializedBytes, startPosition, serializedLength);
        fieldsChunk->setSerializedBytes(serializedBytes);
        CHUNK_CHECK_USAGE(B(serializedBytes->size()) == chunk->getChunkLength(), "serialized length is incorrect: serialized=%ld, chunk=%ld", serializedBytes->size(), B(chunk->getChunkLength()).get());
    }
    else {
        MemoryOutputStream chunkStream(fieldsChunk->getChunkLength());
        serialize(chunkStream, fieldsChunk);
        checkSerializer(chunk, chunkStream);
        stream.writeBytes(chunkStream.getData(), offset, length == b(-1) ? chunk->getChunkLength() - offset : length);
        ChunkSerializer::totalSerializedLength += chunkStream.getLength();
        auto serializedBytes = new std::vector<uint8_t>();
        chunkStream.copyData(*serializedBytes);
        fieldsChunk->setSerializedBytes(serializedBytes);
        CHUNK_CHECK_USAGE(B(serializedBytes->size()) == chunk->getChunkLength(), "serialized length is incorrect: serialized=%ld, chunk=%ld", serializedBytes->size(), B(chunk->getChunkLength()).get());
    }
}

const Ptr<Chunk> FieldsChunkSerializer::deserialize(MemoryInputStream& stream, const std::type_info& typeInfo) const
{
    auto startPosition = stream.getPosition();
    auto fieldsChunk = staticPtrCast<FieldsChunk>(deserialize(stream));
    auto endPosition = stream.getPosition();
    auto chunkLength = endPosition - startPosition;
    ChunkSerializer::totalDeserializedLength += chunkLength;
    fieldsChunk->setChunkLength(chunkLength);
    auto serializedBytes = new std::vector<uint8_t>();
    stream.copyData(*serializedBytes, startPosition, chunkLength);
    fieldsChunk->setSerializedBytes(serializedBytes);
    CHUNK_CHECK_USAGE(B(serializedBytes->size()) == fieldsChunk->getChunkLength(), "serialized length is incorrect: serialized=%ld, chunk=%ld", serializedBytes->size(), B(fieldsChunk->getChunkLength()).get());
    return fieldsChunk;
}

} // namespace
