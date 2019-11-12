Queue Filler
============

In this step, an active packet sink (ActivePacketSink) periodically pops packets from a queue (PacketQueue).
Whenever the queue becomes empty, a queue filler module (QueueFiller) pushes a packet into it.

TODO

The network contains ... TODO

.. figure:: media/QueueFillerNetwork.png
   :width: 80%
   :align: center

.. figure:: media/QueueFiller.png
   :width: 50%
   :align: center

**TODO** Config

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network QueueFillerTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config QueueFiller
   :end-at: collectionInterval
   :language: ini
