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
 * User implementation which enforces the restrictions affecting the user
 * accessing the user. If permission to do so is granted (ADMINISTER
 * permission), restrictions which affect the user represented by the user
 * object may also be managed.
 */
public class RestrictedExternalUser extends DelegatingUser {

    /**
     * Logger for this class.
     */
    private final static Logger logger = LoggerFactory.getLogger(RestrictedExternalUser.class);

    /**
     * The UserContext of the user accessing this object.
     */
    private final RestrictedExternalUserContext userContext;

    /**
     * Creates a new RestrictedUser which wraps the given user. Any
     * restrictions which apply to the user associated with the given
     * UserContext and which affect access to users are enforced. If permission
     * to do so is granted (ADMINISTER permission), restrictions which affect
     * the user represented by the user object may be managed by the user of
     * the UserContext.
     *
     * @param userContext
     *     The UserContext of the user accessing the user object.
     *
     * @param user
     *     The user object that the user is attempting to access.
     */
    public RestrictedExternalUser(RestrictedExternalUserContext userContext,
            User user) {
        super(user);
        this.userContext = userContext;
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

    /**
     * Returns whether the user accessing this user object has permission to
     * view or set attributes which implement restrictions defined by this
     * extension. A user may view and manipulate the restrictions of other
     * users only if they have ADMINISTER permission on that user or general,
     * system-wide ADMINISTER permission.
     *
     * @return
     *     true if the user accessing this user object should be able to view
     *     and manipulate the attributes which implement restrictions defined
     *     by this extension, false otherwise.
     */
    private boolean canAccessRestrictedAttributes() {

        User self = userContext.self();

        // Attempt to determine whether the user has ADMINISTER permission
        try {
            Permissions permissions = userContext.self().getEffectivePermissions();
            return permissions.getSystemPermissions().hasPermission(SystemPermission.Type.ADMINISTER)
                    || permissions.getUserPermissions().hasPermission(ObjectPermission.Type.ADMINISTER, getIdentifier());
        }

        // Assume no permissions if read fails
        catch (GuacamoleException e) {
            logger.warn("Assuming no administrative permissions for user "
                    + "\"{}\" accessing user \"{}\". An error within the "
                    + "extension storing the user being accessed prevents "
                    + "reading permissions: {}.", self.getIdentifier(),
                    getIdentifier(), e.getMessage());
            logger.debug("Unable to read user/system permissions.", e);
            return false;
        }

    }

    @Override
    public void setAttributes(Map<String, String> attributes) {
        super.setAttributes(userContext.filterAttributes(canAccessRestrictedAttributes(), attributes));
    }

    @Override
    public Map<String, String> getAttributes() {
        return userContext.filterAttributes(canAccessRestrictedAttributes(), super.getAttributes());
    }

}
