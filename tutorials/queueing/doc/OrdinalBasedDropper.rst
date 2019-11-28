Ordinal Based Dropper
=====================

In this step, packets are produced periodically by an active packet source
(ActivePacketSource). The packets are consumed by a passive packet sink (PassivePacketSink).
Packets are passed through from the source to the sink by a dropper (OrdinalBasedDropper).
Every second packet is dropped based on its ordinal number.

The network contains ... TODO

.. figure:: media/OrdinalBasedDropper.png
   :width: 80%
   :align: center

**TODO** Config

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network OrdinalBasedDropperTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config OrdinalBasedDropper
   :end-at: dropsVector
   :language: ini
