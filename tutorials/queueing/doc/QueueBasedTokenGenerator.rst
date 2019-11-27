Generating Tokens When a Queue Becomes Empty
============================================

The :ned:`QueueBasedTokenGenerator` module generates tokens into a token-based server when an observed queue becomes empty.
The module can be used by applications to create traffic that completely utilizes a network interface,
for example.

.. figure:: media/QueueBasedTokenGenerator.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network QueueBasedTokenGenerator
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config QueueBasedTokenGenerator
   :end-at: collectionInterval
   :language: ini
