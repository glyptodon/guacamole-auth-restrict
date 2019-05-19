/*
 * Copyright (C) 2019 Glyptodon, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.glyptodon.guacamole.auth.restrict.user;

import com.glyptodon.guacamole.auth.restrict.Restricted;
import java.util.Set;
import org.apache.guacamole.GuacamoleException;
import com.glyptodon.guacamole.auth.restrict.Restriction;
import com.glyptodon.guacamole.auth.restrict.connection.ConnectionManager;
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedExternalConnection;
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedExternalConnectionGroup;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;

/**
 * UserContext implementation which enforces additional restrictions on users
 * and the members of user groups based on custom attributes.
 */
public class RestrictedExternalUserContext extends DelegatingUserContext
        implements Restricted {

    /**
     * A Form which describes the custom attributes used by this extension to
     * represent and enforce additional restrictions.
     */
    private static final Form RESTRICTIONS = new Form("addl-restrict", Arrays.asList(
        Restriction.DISALLOW_CONCURRENT.asField(),
        Restriction.FORCE_READ_ONLY.asField()
    ));

    /**
     * The connection manager tracking connection usage of connections and
     * connection groups within this UserContext.
     */
    private final ConnectionManager manager;

    /**
     * The restrictions that apply to the wrapped UserContext.
     */
    private final Set<Restriction> restrictions;

    /**
     * Creates a new RestrictedUserContext which wraps the given UserContext,
     * applying the given restrictions.
     *
     * @param manager
     *     The connection manager instance that should be used to track
     *     connection usage within this user context.
     *
     * @param restrictions
     *     The restrictions to apply to the given UserContext.
     *
     * @param userContext
     *     The UserContext restrict access to.
     */
    public RestrictedExternalUserContext(ConnectionManager manager,
            Set<Restriction> restrictions, UserContext userContext) {
        super(userContext);
        this.manager = manager;
        this.restrictions = restrictions;
    }

    /**
     * Returns the connection manager that should be used to establish
     * connections to any connection or connection group accessed via this
     * RestrictedUserContext.
     *
     * @return
     *     The connection manager that should be used to establish any
     *     connections.
     */
    public ConnectionManager getConnectionManager() {
        return manager;
    }

    @Override
    public Set<Restriction> getRestrictions() {
        return restrictions;
    }

    @Override
    public Directory<User> getUserDirectory() throws GuacamoleException {
        return new DecoratingDirectory<User>(super.getUserDirectory()) {

            @Override
            protected User decorate(User object)
                    throws GuacamoleException {
                return new RestrictedExternalUser(RestrictedExternalUserContext.this, object);
            }

            @Override
            protected User undecorate(User object)
                    throws GuacamoleException {
                assert(object instanceof RestrictedExternalUser);
                return ((RestrictedExternalUser) object).getUnrestrictedUser();
            }

        };
    }

    @Override
    public Directory<ConnectionGroup> getConnectionGroupDirectory()
            throws GuacamoleException {
        return new DecoratingDirectory<ConnectionGroup>(super.getConnectionGroupDirectory()) {

            @Override
            protected ConnectionGroup decorate(ConnectionGroup object)
                    throws GuacamoleException {
                return new RestrictedExternalConnectionGroup(RestrictedExternalUserContext.this, object);
            }

            @Override
            protected ConnectionGroup undecorate(ConnectionGroup object)
                    throws GuacamoleException {
                assert(object instanceof RestrictedExternalConnectionGroup);
                return ((RestrictedExternalConnectionGroup) object).getUnrestrictedConnectionGroup();
            }

        };
    }

    @Override
    public Directory<Connection> getConnectionDirectory()
            throws GuacamoleException {
        return new DecoratingDirectory<Connection>(super.getConnectionDirectory()) {

            @Override
            protected Connection decorate(Connection object)
                    throws GuacamoleException {
                return new RestrictedExternalConnection(RestrictedExternalUserContext.this, object);
            }

            @Override
            protected Connection undecorate(Connection object)
                    throws GuacamoleException {
                assert(object instanceof RestrictedExternalConnection);
                return ((RestrictedExternalConnection) object).getUnrestrictedConnection();
            }

        };
    }

    /**
     * Returns a collection of Form objects which includes a Form describing
     * the custom attributes used by this extension. The Form objects from
     * the UserContext being wrapped are included.
     *
     * @param attributes
     *     The Form objects describing the attributes declared by the
     *     UserContext being wrapped.
     *
     * @return
     *     A Collection of Form objects which includes all of the given Form
     *     objects, as well as the Form that describes the custom attributes
     *     used by this extension.
     */
    private Collection<Form> getDecoratedAttributes(Collection<Form> attributes) {
        Collection<Form> decoratedAttributes = new ArrayList<>(attributes.size() + 1);
        decoratedAttributes.addAll(attributes);
        decoratedAttributes.add(RESTRICTIONS);
        return decoratedAttributes;
    }

    /**
     * Filters the given map of attribute name/value pairs, returning a
     * potentially new map which contains only the attributes that the
     * user has permission to view or modify.
     *
     * @param isAdmin
     *     Whether the user has permission to view or modify the custom
     *     attributes managed by this extension.
     *
     * @param attributes
     *     The attributes to filter.
     *
     * @return
     *     A map of only those attribute name/value pairs which the user
     *     has permission to view or modify.
     */
    public Map<String, String> filterAttributes(boolean isAdmin,
            Map<String, String> attributes) {

        Map<String, String> filteredAttributes = new HashMap<>(attributes);
        for (Restriction restriction : Restriction.values()) {

            // Ensure restriction attributes are always defined if user has
            // administrative permissions
            if (isAdmin)
                filteredAttributes.putIfAbsent(restriction.getAttributeName(), null);

            // If user does not have administrative permissions, block access
            // to all restriction attributes
            else
                filteredAttributes.remove(restriction.getAttributeName());

        }

        return filteredAttributes;

    }

    @Override
    public Collection<Form> getUserAttributes() {
        return getDecoratedAttributes(super.getUserAttributes());
    }

}
