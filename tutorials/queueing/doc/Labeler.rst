Labeling Packets with Text
==========================

The :ned:`LabelClassifier` module attaches a label
to incoming packets based on a configured packet classifier function.
The :ned:`LabelClassifier` module classifies packets according to the attached label.

The :ned:`LabelClassifier` module attaches a text label
to incoming packets based on a configured packet classifier function.
Based on the attached label, the :ned:`LabelClassifier` module classifies packets to
one of its outputs.

This step demonstrates using the :ned:`ContentBasedLabeler` and the :ned:`LabelClassifier`
modules to classify packets according to a packet classifier function.
The labeler labels the packets according to the classifier function, and the classifier
classifies them according to the attached label.

.. what is it about?

   -its about classifying packets
   -the labeler filters them and labels them according to something
   -and the classifier classifies them
   -it does the same as the content based classifier but the function is in two modules
   that can be at different locations in the queueing network

In this step, packets are produced periodically by an active packet source
(:ned:`ActivePacketSource`). The packets are consumed by two passive packet sinks
(:ned:`PassivePacketSink`). The single source is connected to the two sinks using a
classifier (:ned:`LabelClassifier`). The classifier forwards packets alternately to
one or the other sink based on the packet's label. The label is attached by
a PacketLabeler based on the packet length.

.. figure:: media/Labeler.png
   :width: 90%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network LabelerTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Labeler
   :end-at: labelsToGateIndices
   :language: ini
