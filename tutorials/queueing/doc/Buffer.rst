Storing Packets on Behalf of Multiple Queues
============================================

.. Buffer
   Storing packets in a buffer shared among multiple queues

This step demonstrates the :ned:`PacketBuffer` module. The module stores packets on
behalf of multiple queues, acting as a shared packet buffer for them.
Instead of each individual queue having a capacity store a given number of packets,
the packets are stored by the buffer for the queues.
the buffer's capacity

-the queues dont have packet capacity individually
-instead, since packets are stored in the buffer, the buffer's capacity is relevant.
-so if there are two queues with 5 packet capacity, and 2 queues and a buffer with 10 packet
capacity, one of the queues could store 10 packets while the other stores 0
-the buffer records which packet belongs in which queue
-so the buffer takes the packet storing mechanism from the queues (that mean capacity as well)
-so the queues have shared packet storing mechanism and packet capacity
-while a record is kept about which packet belongs to which queue

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
