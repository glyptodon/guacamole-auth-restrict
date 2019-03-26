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

import com.glyptodon.guacamole.auth.restrict.user.groups.RestrictedUserGroupDirectory;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractUserContext;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserGroup;

/**
 * UserContext implementation providing access specifically to the data defined
 * by the "guacamole-auth-restrict" extension itself.
 */
public class RestrictedUserContext extends AbstractUserContext {

    /**
     * The AuthenticationProvider that created this UserContext.
     */
    private final AuthenticationProvider authProvider;

    /**
     * The User object representing the current user.
     */
    private final User self;

    /**
     * A directory containing all user groups defined by the
     * "guacamole-auth-restrict" extension.
     */
    private final RestrictedUserGroupDirectory restrictedUserGroupDirectory;

    /**
     * Creates a RestrictedUserContext which provides access to the data
     * specifically defined by the "guacamole-auth-restrict" extension.
     *
     * @param authProvider
     *     The AuthenticationProvider that created this UserContext.
     *
     * @param authenticatedUser
     *     The user that will be given access to this UserContext.
     *
     * @param restrictedUserGroupDirectory
     *     A directory containing all user groups defined by the
     *     "guacamole-auth-restrict" extension.
     */
    public RestrictedUserContext(AuthenticationProvider authProvider,
            AuthenticatedUser authenticatedUser,
            RestrictedUserGroupDirectory restrictedUserGroupDirectory) {
        this.authProvider = authProvider;
        this.restrictedUserGroupDirectory = restrictedUserGroupDirectory;
        this.self = new RestrictedUser(authenticatedUser.getIdentifier(), restrictedUserGroupDirectory);
    }

    @Override
    public User self() {
        return self;
    }

    @Override
    public AuthenticationProvider getAuthenticationProvider() {
        return authProvider;
    }

    @Override
    public Directory<UserGroup> getUserGroupDirectory() throws GuacamoleException {
        return restrictedUserGroupDirectory;
    }

}
