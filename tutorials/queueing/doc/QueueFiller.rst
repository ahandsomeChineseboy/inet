Queue Filler
============

This step demonstrates the :ned:`QueueFiller` module, which creates packets whenever
a connected queue becomes empty. The module can be used to saturate a channel. TODO

In this step, an active packet sink (:ned:`ActivePacketSink`) periodically pops packets from a queue (:ned:`PacketQueue`).
Whenever the queue becomes empty, a queue filler module (:ned:`QueueFiller`) pushes a packet into it.

.. figure:: media/QueueFillerNetwork.png
   :width: 80%
   :align: center

.. figure:: media/QueueFiller.png
   :width: 50%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network QueueFillerTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config QueueFiller
   :end-at: collectionInterval
   :language: ini
