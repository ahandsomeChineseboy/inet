
package inet.tutorials.queueing;

import inet.queueing.source.ActivePacketSource;
import inet.queueing.sink.ActivePacketSink;
import inet.queueing.queue.PriorityQueue;

network PriorityQueueNetwork
{
    @display("bgb=600,200");
    submodules:
        producer: ActivePacketSource {
            @display("p=100,100");
        }
        queue: PriorityQueue {
            @display("p=300,100");
        }
        collector: ActivePacketSink {
            @display("p=500,100");
        }
    connections allowunconnected:
        producer.out --> queue.in;
        queue.out --> collector.in;
}

