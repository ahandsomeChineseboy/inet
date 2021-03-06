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

#include "inet/queueing/scheduler/PacketScheduler.h"

namespace inet {
namespace queueing {

Define_Module(PacketScheduler);

void PacketScheduler::initialize(int stage)
{
    PacketSchedulerBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        const char *schedulerClass = par("schedulerClass");
        packetSchedulerFunction = check_and_cast<IPacketSchedulerFunction *>(createOne(schedulerClass));
    }
}

int PacketScheduler::schedulePacket()
{
    return packetSchedulerFunction->schedulePacket(providers);
}

} // namespace queueing
} // namespace inet

