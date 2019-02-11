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

import java.util.Map;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.DelegatingUser;
import org.apache.guacamole.net.auth.Permissions;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.permission.ObjectPermission;
import org.apache.guacamole.net.auth.permission.SystemPermission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User implementation which provides access to custom attributes controlling
 * restrictions. Access to restriction attributes is given only if the user
 * accessing this object has ADMINISTER permission. If the user accessing the
 * object lacks ADMINISTER permission, access to the attributes controlling
 * restrictions is blocked.
 */
public class RestrictedUser extends DelegatingUser {

    /**
     * Logger for this class.
     */
    private final Logger logger = LoggerFactory.getLogger(RestrictedUser.class);

    /**
     * The UserContext of the user accessing this object.
     */
    private final RestrictedUserContext userContext;

    /**
     * Creates a new RestrictedUser which wraps the given user, providing
     * selective access to the custom attributes which control the additional
     * restrictions provided by this extension. Access to the custom attributes
     * is provided only to users having ADMINSTER permission.
     *
     * @param userContext
     *     The UserContext of the user accessing the given user.
     *
     * @param user
     *     The user that the user is attempting to access.
     */
    public RestrictedUser(RestrictedUserContext userContext, User user) {
        super(user);
        this.userContext = userContext;
    }

    /**
     * Filters the given map of attribute name/value pairs, returning a
     * potentially new map which contains only the attributes that the
     * user accessing this object has permission to view or modify. The custom
     * attributes managed by this extension will be present only if the user
     * accessing this object has ADMINSTER permission.
     *
     * @param attributes
     *     The attributes to filter.
     *
     * @return
     *     A map of only those attribute name/value pairs which the user
     *     accessing this object has permission to view or modify.
     */
    private Map<String, String> filterAttributes(Map<String, String> attributes) {

        // If a failure prevents retrieving permissions, assume the user lacks
        // adminitrative privileges
        boolean isAdmin = false;

        // Attempt to determine whether the user has ADMINISTER permission
        try {
            Permissions permissions = userContext.self().getEffectivePermissions();
            isAdmin = permissions.getSystemPermissions().hasPermission(SystemPermission.Type.ADMINISTER)
                    || permissions.getUserPermissions().hasPermission(ObjectPermission.Type.ADMINISTER, getIdentifier());
        }
        catch (GuacamoleException e) {
            logger.warn("A failure in the underlying extension is preventing "
                    + "retrieval of user permissions. The current user will "
                    + "be assumed to NOT have administrative privileges, and "
                    + "will not be able to see/manipulate the attributes "
                    + "controlling additional restrictions.");
            logger.debug("Unable to determine whether current user has ADMINISTER permission.", e);
        }

        // Provide access to restriction attributes only if ADMINISTER
        // permission can be verified
        return userContext.filterAttributes(isAdmin, attributes);

    }

    @Override
    public void setAttributes(Map<String, String> attributes) {
        super.setAttributes(filterAttributes(attributes));
    }

    @Override
    public Map<String, String> getAttributes() {
        return filterAttributes(super.getAttributes());
    }

    /**
     * Returns the original User wrapped by this RestrictedUser. The returned
     * User will not be affected by the restrictions otherwise enforced by this
     * extension.
     *
     * @return
     *     The original User wrapped by this RestrictedUser.
     */
    public User getUnrestrictedUser() {
        return getDelegateUser();
    }

}
