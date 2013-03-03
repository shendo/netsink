netsink
=======

Network sinkhole for isolated malware analysis.

Overview
--------

``netsink`` is a network daemon that will bind to any number of configured IP ports 
and provide fake services in an attempt to convince running malware that it has an active
Internet connection.

Getting Started
---------------
Install using ``pip``: ::
    pip install netsink

Start the ``netsink`` listeners with the default configuration: ::
    netsink

You should see output similar to the following, showing the bound ports: ::
    2013-03-03 21:01:02,710 [netsink] INFO: Listener 'http' awaiting TCP activity on port/s [80, 8000, 8080, 8090]
    2013-03-03 21:01:02,717 [netsink] INFO: Listener 'https' awaiting SSL activity on port/s [443, 8443]
    2013-03-03 21:01:02,726 [netsink] INFO: Listener 'dns' awaiting UDP activity on port/s [53]
    2013-03-03 21:01:02,726 [netsink] INFO: Waiting...

To test, open a browser on the same host and navigate to https://127.0.0.1/testing and 
you should see a netsink response page.

Client Setup
------------
To be useful a client machine must be forced to redirect their traffic to the services
on the ``netsink`` host.  This can be achieved in several ways.

* Static DNS Configuration.  ``netsink`` includes a DNS server that will advertise
itself as the destination for any client DNS requests (or as otherwise configured).  
Change the client's network interface to use the ``netsink`` host's address as its 
DNS server.

* DHCP Configuration.  Not currently provided by the ``netsink`` package, however, if
installing on a unix/linux platform, using the operating system's DHCP server package
can be effective (for example ``isc-dhcp-server`` on ubuntu).  Set the ``netsink`` host's
as the address to be returned for DNS and Default Gateway to the clients.  Set the client's
network interface to obtain an address automatically.

To test, ensure that any changes have been applied to the client's network interface.
On Windows, in a command window: ::
 ipconfig /all

The ``netsink`` host's address should be listed as the DNS server on the applicable network 
interface.  Now open a web browser on the client and navigate to www.google.com  you 
should instead see the netsink response page and the DNS/HTTP requests logged on the server.

Goals
-----

The primary project goals are:

* Provide malware with communication end points to assist execution and elicit network traffic.
* Straight-forward installation/deployment.  Should work out-of-the-box for most scenarios.
* Easy configuration and extension.  Adding custom port ranges and services should be as simple as possible.

Features
--------

This project is still in early development, as such the feature set is limited.

* DNS redirection based on simple config file
* HTTP/HTTPS serving of static files based on url regexes
* Listening port ranges easily configurable and separate from the modules that handle the traffic. 

Planned Additions:

* Internal DHCP server to auto configure clients
* Automatic connection redirection for platforms that support ``iptables``
* Expand available fake services to include IRC, SMTP, FTP, etc.
* Better documentation

Issues
------

Source code for ``netsink`` is hosted on `GitHub`_. Any bug reports or feature
requests can be made using GitHub's `issues system`_.

.. _GitHub: https://github.com/shendo/netsink
.. _issues system: https://github.com/shendo/netsink/issues
