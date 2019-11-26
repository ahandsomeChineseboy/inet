Priority Buffer
===============

This step demonstrates the :ned:`PriorityBuffer` module. The module has a configurable
packet dropping stragegy; by default, the module drops packets belonging to the last
connected queue.

The :ned:`PriorityBuffer` module has a configurable
packet dropping stragegy. By default, the module drops packets belonging to the last
connected queue.

In this step, packets are produced periodically (randomly) by two active packet
sources (:ned:`ActivePacketSource`). The packets are collected periodically (randomly)
by two active packet sinks (:ned:`ActivePacketSink`). The sources and the sinkes are
connected by packet queues (:ned:`PacketQueue`) and packets are stored in shared packet
buffer (:ned:`PacketBuffer`). The packet buffer drops packets when it gets overloaded
prioritizing over the packet queues.

.. figure:: media/PriorityBuffer.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network PriorityBufferTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config PriorityBuffer
   :end-at: packetCapacity
   :language: ini
