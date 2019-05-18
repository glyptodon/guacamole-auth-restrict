guacamole-auth-restrict
=======================

**guacamole-auth-restrict** is an authentication extension for [Apache
Guacamole](http://guacamole.apache.org/) which enforces additional restrictions
on users and the members of user groups. These restrictions may be specified
through either of two possible methods:

1. User attributes, which will be presented as fields within the user edit
   screen for users managed by extensions that support administration (such as
   the various database authentication extensions).
2. Membership within predefined, special user groups.

If defining restrictions via user attributes, the scope of the restrictions is
isolated to the objects within the extension storing those attributes.

If defining restrictions via group membership, keep in mind that **restrictions
will only take effect if membership in the relevant group is defined by the
backend authenticating the user**. This means that if users will be
authenticating against LDAP, it is not sufficient to associate those users with
the applicable group within a database backend like MySQL or PostgreSQL; they
must be added to an LDAP group with the same name.

Additional restrictions
-----------------------

Default group name | Attribute name | Description
------------------ | -------------- | -----------
`ReadOnlyUsers` | `addl-restrict-force-read-only` | Blocks interaction with all connections and connection groups. The name of the group may be overridden with the `read-only-group-name` property.

