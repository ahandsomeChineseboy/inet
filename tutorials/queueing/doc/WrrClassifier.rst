Weighted Round-Robin Classifier
===============================

This step demonstrates the Weighted Round-Robin Classifier (:ned:`WrrClassifier`).

In this step, packets are produced periodically by an active packet source
(:ned:`ActivePacketSource`). The packets are consumed by two passive packet sinks
(:ned:`PassivePacketSink`). The single source is connected to the two sinks using a
classifier (:ned:`WrrClassifier`). The classifier forwards packets alternately to
one or the other sink.

.. figure:: media/Classifier.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network WrrClassifierTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config WrrClassifier
   :end-at: weights
   :language: ini
