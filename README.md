guacamole-auth-restrict
=======================

**guacamole-auth-restrict** is an authentication extension for [Apache
Guacamole](http://guacamole.apache.org/) which enforces additional restrictions
on users and the members of user groups. These restrictions are dictated by
custom attributes that are added made available for the users and user groups
defined by other extensions. If the write support for users and user groups
is provided (such as by the database extensions included with Guacamole), these
attributes will be editable by administrators within Guacamole's administrative
interface.

Additional restrictions
-----------------------

Attribute name                  | Description
--------------------------------|-------------
`addl-restrict-force-read-only` | Blocks interaction with all connections and connection groups.

