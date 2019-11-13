Network
=======

This step demonstrates how to combine queueing components to create a simplistic network.
The network features two hosts communicating. The hosts are connected by a cable module which
adds delay to the connection. Each host contains a packet source and a packet sink application,
connected to the network level by an interface module.

.. figure:: media/Network_TestCable.png
   :width: 30%
   :align: center

.. figure:: media/Network.png
   :width: 50%
   :align: center

.. figure:: media/Network_TestHost.png
   :width: 60%
   :align: center

.. figure:: media/NetworkInterface.png
   :width: 50%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network TestNetworkTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: module TestHost
   :end-before: //----
   :language: ned

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: module TestInterface
   :end-before: //----
   :language: ned

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: module TestCable
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config TestNetwork
   :end-at: delay
   :language: ini
