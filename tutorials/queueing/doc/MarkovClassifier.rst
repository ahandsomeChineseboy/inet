Markov Classifier
=================

In this step, packets are periodically (randomly) collected by two active sinks
(:ned:`ActivePacketSink`). One sink collects packets with a slower rate while the other
sink uses a faster rate. The two packet sinks are combined using a Markov
chain (:ned:`MarkovClassifier`) with random transition matrix and random wait intervals. The packets are
provided by a single passive source (:ned:`PassivePacketSource`).

.. figure:: media/Burst2.png
   :width: 80%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network MarkovClassifierTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config MarkovClassifier
   :end-at: waitIntervals
   :language: ini
