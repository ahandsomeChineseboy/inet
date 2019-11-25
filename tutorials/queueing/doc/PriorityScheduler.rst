Priority Scheduler
==================

This step demonstrates the :ned:`PriorityScheduler` module. The module pops packets from the first
connected non-empty queue or packet provider.

In this step, packets are collected periodically by an active packet sink
(:ned:`ActivePacketSink`). The packets are produced by two active packet sources
(:ned:`ActivePacketSource`). The sources are connected to FIFO queues (:ned:`PacketQueue`)
where packets are stored temporarily. The single sink is connected to the
queues using a scheduler (:ned:`PriorityScheduler`). The scheduler forwards packets
from the queues to the sink in a prioritized way, favoring the first queue.

.. figure:: media/PriorityScheduler.png
   :width: 90%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network PrioritySchedulerTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config PriorityScheduler
   :end-at: collectionInterval
   :language: ini
