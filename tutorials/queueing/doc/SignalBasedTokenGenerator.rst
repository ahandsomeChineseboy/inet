Generating Tokens Based on Received Signals
===========================================

The :ned:`SignalBasedTokenGenerator` module generates tokens based on received signals.

.. figure:: media/SignalBasedTokenGenerator.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network SignalBasedTokenGenerator
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config SignalBasedTokenGenerator
   :end-at: serverModule
   :language: ini
