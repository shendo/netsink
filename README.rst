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

Deployment architecture is very flexible and depends on current analysis tools/environment.
As an example, we deploy netsink within our virtualised, automatic dynamic analysis sandboxes,
as a dedicated virtual machine sharing the same virtual network as the clients.  

* Create a virtual machine on your analysis network
* Install your favourite flavour of Linux
* Set the interface (on the shared virtual network as your guests) with a static IP
* Install the latest ``netsink`` package
* run ``start.py``
* Either configure dhcpd on your netsink host (and set clients to obtain IP automatically) or set the DNS/gateway address on your clients to the netsink IP statically.
* Test by trying to web browse to www.google.com on a client, you should instead see a dummy netsink webpage

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
