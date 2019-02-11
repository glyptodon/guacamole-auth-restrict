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

import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.guacamole.GuacamoleException;
import com.glyptodon.guacamole.auth.restrict.Restriction;
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedConnection;
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedConnectionGroup;
import org.apache.guacamole.form.Form;
import org.apache.guacamole.net.auth.Attributes;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.UserGroup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * UserContext implementation which enforces additional restrictions on users
 * and the members of user groups based on custom attributes.
 */
public class RestrictedUserContext extends DelegatingUserContext {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(RestrictedUserContext.class);

    /**
     * The AuthenticatedUser representing the user affected by the additional
     * restrictions enforced by this extension.
     */
    private final AuthenticatedUser authenticatedUser;

    /**
     * A Form which describes the custom attributes available on users and
     * user groups for additional restrictions.
     */
    private static final Form RESTRICTIONS = new Form("addl-restrict", Arrays.asList(
        Restriction.FORCE_READ_ONLY.asField()
    ));

    /**
     * Creates a new RestrictedUserContext which restricts wraps the given
     * UserContext, restricting access to its data based on custom attributes.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser representing the user affected by the
     *     additional restrictions enforced by this extension.
     *
     * @param userContext
     *     The UserContext restrict access to.
     */
    @AssistedInject
    public RestrictedUserContext(@Assisted AuthenticatedUser authenticatedUser,
            @Assisted UserContext userContext) {
        super(userContext);
        this.authenticatedUser = authenticatedUser;
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
     * Returns the set of restrictions which apply to the current user, as
     * dictated by the attributes associated with the given object.
     *
     * @param object
     *     The object whose attributes should be used to determine the
     *     restrictions that apply.
     *
     * @return
     *     The set of restrictions which apply to the current user according to
     *     the given object.
     */
    private EnumSet<Restriction> getRestrictionsFromAttributes(Attributes object) {

        EnumSet<Restriction> restrictions = EnumSet.allOf(Restriction.class);

        // Remove all restrictions which are not enabled according to the
        // attributes associated with the given object
        Map<String, String> attributes = object.getAttributes();
        restrictions.removeIf(restriction -> !restriction.isSet(attributes));

        return restrictions;

    }

    /**
     * Returns the set of all restrictions which apply to the current user. The
     * restrictions that explicitly apply to the current user or any associated
     * user group are taken into account. Note that as this will potentially
     * query the attributes of multiple objects, this function should be called
     * only when necessary.
     *
     * @return
     *     The set of all restrictions which apply to the current user.
     */
    public Set<Restriction> getRestrictions() {

        // Retrieve the restrictions which apply explicitly to the current user
        User self = getDelegateUserContext().self();
        EnumSet<Restriction> restrictions = getRestrictionsFromAttributes(self);

        // Attempt to include the restrictions which apply to any associated
        // user groups
        try {

            // Retrieve all effective user groups
            Directory<UserGroup> groupDirectory = getDelegateUserContext().getUserGroupDirectory();
            Collection<UserGroup> groups = groupDirectory.getAll(authenticatedUser.getEffectiveUserGroups());

            // Apply the restrictions from each group
            for (UserGroup group : groups)
                restrictions.addAll(getRestrictionsFromAttributes(group));

        }
        catch (GuacamoleException e) {
            logger.warn("A failure in the underlying extension is preventing "
                    + "retrieval of user groups. Restrictions which apply to "
                    + "user groups may not be taken into account.");
            logger.debug("Unable to retrieve the user groups applying to the current user.", e);
        }

        return restrictions;

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
    public Collection<Form> getUserGroupAttributes() {
        return getDecoratedAttributes(super.getUserGroupAttributes());
    }

    @Override
    public Collection<Form> getUserAttributes() {
        return getDecoratedAttributes(super.getUserAttributes());
    }

    @Override
    public Directory<UserGroup> getUserGroupDirectory()
            throws GuacamoleException {
        return new DecoratingDirectory<UserGroup>(super.getUserGroupDirectory()) {

            @Override
            protected UserGroup decorate(UserGroup object) throws GuacamoleException {
                return new RestrictedUserGroup(RestrictedUserContext.this, object);
            }

            @Override
            protected UserGroup undecorate(UserGroup object) throws GuacamoleException {
                assert(object instanceof RestrictedUserGroup);
                return ((RestrictedUserGroup) object).getUnrestrictedUserGroup();
            }

        };
    }

    @Override
    public Directory<User> getUserDirectory()
            throws GuacamoleException {
        return new DecoratingDirectory<User>(super.getUserDirectory()) {

            @Override
            protected User decorate(User object) throws GuacamoleException {
                return new RestrictedUser(RestrictedUserContext.this, object);
            }

            @Override
            protected User undecorate(User object) throws GuacamoleException {
                assert(object instanceof RestrictedUser);
                return ((RestrictedUser) object).getUnrestrictedUser();
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
                return new RestrictedConnectionGroup(RestrictedUserContext.this, object);
            }

            @Override
            protected ConnectionGroup undecorate(ConnectionGroup object)
                    throws GuacamoleException {
                assert(object instanceof RestrictedConnectionGroup);
                return ((RestrictedConnectionGroup) object).getUnrestrictedConnectionGroup();
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
                return new RestrictedConnection(RestrictedUserContext.this, object);
            }

            @Override
            protected Connection undecorate(Connection object)
                    throws GuacamoleException {
                assert(object instanceof RestrictedConnection);
                return ((RestrictedConnection) object).getUnrestrictedConnection();
            }

        };
    }

}
