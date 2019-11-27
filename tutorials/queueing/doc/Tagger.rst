Requesting Protocol-Specific Behavior for Packets
=================================================

.. Requesting Protocol Specific Behavior (too generic in the sense that the reader doesn't know what behavior: VLAN, outgoing interface)

This step demonstrates the :ned:`PacketTagger` module, which attaches various request tags to packets.

In this step, packets are produced periodically by an active packet source
(:ned:`ActivePacketSource`). The packets pass through a packet tagger which attaches
a HopLimitReq tag. The packets are consumed by a passive packet sink (:ned:`PassivePacketSink`).

.. figure:: media/Tagger.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network TaggerTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config Tagger
   :end-at: hopLimit
   :language: ini
