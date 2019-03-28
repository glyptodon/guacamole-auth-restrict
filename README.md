guacamole-auth-restrict
=======================

**guacamole-auth-restrict** is an authentication extension for [Apache
Guacamole](http://guacamole.apache.org/) which enforces additional restrictions
on users and the members of user groups. These restrictions are dictated by
user groups and enforced on members of those groups.

Keep in mind that **restrictions will only take effect if membership in the
relevant group is defined by the backend authenticating the user**. This means
that if users will be authenticating against LDAP, it is not sufficient to
associate those users with the applicable group within a database backend like
MySQL or PostgreSQL; they must be added to an LDAP group with the same name.

Additional restrictions
-----------------------

Group name      | Description
----------------|-------------
`ReadOnlyUsers` | Blocks interaction with all connections and connection groups. The name of this group may be overridden with the `read-only-group-name` property.

