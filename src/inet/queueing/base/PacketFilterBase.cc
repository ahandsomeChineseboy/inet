//
// Copyright (C) OpenSim Ltd.
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
// along with this program; if not, see http://www.gnu.org/licenses/.
//

#include "inet/common/ModuleAccess.h"
#include "inet/queueing/base/PacketFilterBase.h"
#include "inet/common/Simsignals.h"

namespace inet {
namespace queueing {

void PacketFilterBase::initialize(int stage)
{
    PacketProcessorBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        inputGate = gate("in");
        outputGate = gate("out");
        auto inputConnectedModule = findConnectedModule(inputGate);
        auto outputConnectedModule = findConnectedModule(outputGate);
        producer = dynamic_cast<IActivePacketSource *>(inputConnectedModule);
        collector = dynamic_cast<IActivePacketSink *>(outputConnectedModule);
        provider = dynamic_cast<IPassivePacketSource *>(inputConnectedModule);
        consumer = dynamic_cast<IPassivePacketSink *>(outputConnectedModule);
        numDroppedPackets = 0;
        droppedTotalLength = b(0);
    }
    else if (stage == INITSTAGE_QUEUEING) {
        if (producer != nullptr)
            checkPushPacketSupport(outputGate);
        if (collector != nullptr)
            checkPopPacketSupport(outputGate);
        if (provider != nullptr)
            checkPopPacketSupport(inputGate);
        if (consumer != nullptr)
            checkPushPacketSupport(inputGate);
    }
}

void PacketFilterBase::pushPacket(Packet *packet, cGate *gate)
{
    if (matchesPacket(packet)) {
        EV_INFO << "Passing through packet " << packet->getName() << "." << endl;
        pushOrSendPacket(packet, outputGate, consumer);
    }
    else {
        EV_INFO << "Filtering out packet " << packet->getName() << "." << endl;
        dropPacket(packet, OTHER_PACKET_DROP);
    }
    numProcessedPackets++;
    processedTotalLength += packet->getTotalLength();
    updateDisplayString();
}

bool PacketFilterBase::canPopSomePacket(cGate *gate)
{
    auto providerGate = inputGate->getPathStartGate();
    while (true) {
        auto packet = provider->canPopPacket(providerGate);
        if (packet == nullptr)
            return false;
        else if (matchesPacket(packet))
            return true;
        else {
            packet = provider->popPacket(providerGate);
            EV_INFO << "Filtering out packet " << packet->getName() << "." << endl;
            dropPacket(packet, OTHER_PACKET_DROP);
        }
    }
}

Packet *PacketFilterBase::popPacket(cGate *gate)
{
    auto providerGate = inputGate->getPathStartGate();
    while (true) {
        auto packet = provider->popPacket(providerGate);
        numProcessedPackets++;
        processedTotalLength += packet->getTotalLength();
        if (matchesPacket(packet)) {
            EV_INFO << "Passing through packet " << packet->getName() << "." << endl;
            animateSend(packet, outputGate);
            return packet;
        }
        else {
            EV_INFO << "Filtering out packet " << packet->getName() << "." << endl;
            dropPacket(packet, OTHER_PACKET_DROP);
            updateDisplayString();
        }
    }
}

void PacketFilterBase::handleCanPushPacket(cGate *gate)
{
    if (producer != nullptr)
        producer->handleCanPushPacket(inputGate);
}

void PacketFilterBase::handleCanPopPacket(cGate *gate)
{
    if (collector != nullptr)
        collector->handleCanPopPacket(outputGate);
}

void PacketFilterBase::dropPacket(Packet *packet, PacketDropReason reason, int limit)
{
    PacketQueueingElementBase::dropPacket(packet, reason, limit);
    numDroppedPackets++;
    droppedTotalLength += packet->getTotalLength();
}

const char *PacketFilterBase::resolveDirective(char directive)
{
    static std::string result;
    switch (directive) {
        case 'd':
            result = std::to_string(numDroppedPackets);
            break;
        case 'k':
            result = droppedTotalLength.str();
            break;
        default:
            return PacketProcessorBase::resolveDirective(directive);
    }
    return result.c_str();
}

} // namespace queueing
} // namespace inet

