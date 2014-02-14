Elastic Shit Shoveler
#####################
:date: 2014-02-12 05:54
:tags: rackspace, jungledisk, build, deployment, api, cloud, python
:category: linux 

Getting Objects from the Sky
============================

This application was created to allow you to download the contents of a Jungle Disk container in your to a local directory.  While the Jungle Disk client is proper way to go about your downloads this client will attempt to mass download rapidly.

Prerequisites :
  * Python => 2.6 < 3.0
  * prettytable >= 0.7.0
  * requests >= 2.2.0


--------

General Overview
^^^^^^^^^^^^^^^^

To use this application you will need the following:
  * A Jungle Disk Account
  * A Token for use with a SWIFT Backend
  * A Region to Get from
  * A Container Name to Download From
  

How to make it all go::

  python shoveler.py -r dfw -a [TENANT-ID] -t [TOKEN-ID] download -c [CONTAINER-NAME] --dir [LOCAL-DIRECTORY]


This application has several command line switches, run ``--help`` for more information on what all of the options are.


NOTICE
------

* This application was built borrowing a lot of code from Turbolift, one of my other applications.
* This super **ALPHA** build and while working as expected and providing a functional build environment you can except wonkyness.
* This application is not a Rackspace sanctioned piece of software and has **Absolutely No** support via Rackspace or the Rackspace community.
* If you have issues with this application and are kind enough to want to report them please create a github issue.


--------


License :
  This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. See "README/LICENSE.txt" for full disclosure of the license associated with this product. Or goto http://www.gnu.org/licenses/

