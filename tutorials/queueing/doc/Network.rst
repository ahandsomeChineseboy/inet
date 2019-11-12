Network
=======

This step demonstrates how to combine queueing components to create a simplistic network.

.. figure:: media/Network_TestCable.png
   :width: 25%
   :align: center

.. figure:: media/Network.png
   :width: 50%
   :align: center

.. figure:: media/Network_TestHost.png
   :width: 60%
   :align: center

.. figure:: media/Network_TestMac.png
   :width: 50%
   :align: center

.. literalinclude:: ../QueueingTutorial.ned
   :start-at: network TestNetworkTutorialStep
   :end-before: //----
   :language: ned

.. literalinclude:: ../omnetpp.ini
   :start-at: Config TestNetwork
   :end-at: delay
   :language: ini
