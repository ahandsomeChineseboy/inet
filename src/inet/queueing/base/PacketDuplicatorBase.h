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

#ifndef __INET_PACKETDUPLICATORBASE_H
#define __INET_PACKETDUPLICATORBASE_H

#include "inet/queueing/base/PacketQueueingElementBase.h"
#include "inet/queueing/contract/IPacketDuplicator.h"

namespace inet {
namespace queueing {

class INET_API PacketDuplicatorBase : public PacketQueueingElementBase, public IPacketDuplicator
{
  protected:
    cGate *inputGate = nullptr;
    IActivePacketSource *producer = nullptr;

    cGate *outputGate = nullptr;
    IPassivePacketSink *consumer = nullptr;

  protected:
    virtual void initialize(int stage) override;
    virtual int getNumPacketDuplicates(Packet *packet) = 0;

  public:
    virtual IPassivePacketSink *getConsumer(cGate *gate) override { return this; }

    virtual bool supportsPushPacket(cGate *gate) override { return true; }
    virtual bool supportsPopPacket(cGate *gate) override { return true; }

    virtual bool canPushSomePacket(cGate *gate) override { return true; }
    virtual bool canPushPacket(Packet *packet, cGate *gate) override { return true; }
    virtual void pushPacket(Packet *packet, cGate *gate) override;

    virtual void handleCanPushPacket(cGate *gate) override;
};

} // namespace queueing
} // namespace inet

#endif // ifndef __INET_PACKETDUPLICATORBASE_H

