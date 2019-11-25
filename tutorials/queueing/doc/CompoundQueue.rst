Compound Queue
==============

This step demonstrates a compound priority queue built from queueing components.
The compound queue contains two packet queues; a classifier pushes packets to the queues
in a round-robin fashion; a priority scheduler pops packets
from the first non-empty queue, thus the first queue has priority over the second.

In this step, packets are produced periodically (randomly) by an active packet
source (:ned:`ActivePacketSource`). The packets are collected periodically (randomly) by
an active packet sink (ActivePacketSink). The source and the sink is connected
by a compound priority queue (ExampleCompoundPacketQueue) where packets are stored temporarily.
This queue contains a classifier (:ned:`PacketClassifier`), two queues (:ned:`PacketQueue`),
and a priorty scheduler (:ned:`PriorityScheduler`).

.. figure:: media/CompoundQueue.png
   :width: 70%
   :align: center

.. figure:: media/CompoundQueue_Queue.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network CompoundPacketQueueTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: module TestCompoundPacketQueue
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config CompoundQueue
   :end-at: weights
   :language: ini
