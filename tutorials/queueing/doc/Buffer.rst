Storing Packets on Behalf of Multiple Queues
============================================

.. Buffer
   Storing packets in a buffer shared among multiple queues

This step demonstrates the :ned:`PacketBuffer` module. The module stores packets on
behalf of multiple queues, acting as a shared packet buffer for them.

In this step, packets are produced at random intervals by two active packet
sources (:ned:`ActivePacketSource`). The packets are collected at random intervals
by two active packet sinks (:ned:`ActivePacketSink`). The sources and the sinks are
connected by packet queues (:ned:`PacketQueue`) and packets are stored in a shared packet
buffer (:ned:`PacketBuffer`). The packet buffer drops packets from the beginning of
the buffer when it gets overloaded.

.. figure:: media/Buffer.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network BufferTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config Buffer
   :end-at: packetCapacity
   :language: ini
