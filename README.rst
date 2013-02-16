netsink
=======

Network sinkhole for isolated malware analysis.

Overview
--------

Netsink is a network daemon that will bind to any number of configured IP ports 
and provide fake services in an attempt to convince running malware that it has an active
Internet connection.

Getting Started
---------------

Network architecture is very flexible and depends on current analysis tools/environment.
As an example, we deploy netsink within our virtualised, automatic dynamic analysis sandboxes,
as a dedicated virtual machine sharing the same virtual network as the clients.

* Create a virtual machine on your analysis network
* Install your favourite flavour of Linux
* Set the interface (on the shared virtual network as your guests) with a static IP
* Install the latest netsink package
* run start.py
* Either configure dhcpd on your netsink host (and set clients to obtain IP automatically) or set 
the DNS/gateway address on your clients to the netsink IP statically.
* Test by trying to web browse to www.google.com on a client, you should instead see a netsink webpage

Goals
-----

The primary project goals are:
* Simply to get malware to talk.  Netsink is just there to provide communication end points.
* Straight-forward installation/deployment.  Should work out-of-the-box for most scenarios.
* Easy configuration and extension.  Adding custom port ranges and protocols should be as simple as possible.

Features
--------

This project is still in early development, as such the feature set is limited.
* DNS redirection based on simple config file
* HTTP/HTTPS serving of static files based on url regexes
* Listening port ranges easily configurable and separate from the modules that handle the traffic. 

Planned Additions:
* Internal DHCP server to auto configure clients
* Automatic connection redirection for platforms that support iptables
* Expand available fake services to include IRC, SMTP, FTP, etc.
* Easy hook points for setting up fake C2 servers for known implant families
* A lot better documentation than this :)

