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
import org.apache.guacamole.net.auth.permission.ObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleObjectPermissionSet;
import org.apache.guacamole.net.auth.simple.SimpleUser;

/**
 * A user of the "guacamole-auth-restrict" extension.
 */
public class RestrictedUser extends SimpleUser {

    /**
     * The directory of user groups accessible by this user.
     */
    private final RestrictedUserGroupDirectory restrictedUserGroupDirectory;

    /**
     * Creates a new RestrictedUser having the given username and read-only
     * access to the groups within the given directory.
     *
     * @param username
     *     The username to assign to the new RestrictedUser.
     *
     * @param restrictedUserGroupDirectory
     *     The directory of all groups defined by the "guacamole-auth-restrict"
     *     extension that are readable by the user.
     */
    public RestrictedUser(String username,
            RestrictedUserGroupDirectory restrictedUserGroupDirectory) {
        super(username);
        this.restrictedUserGroupDirectory = restrictedUserGroupDirectory;
    }

    @Override
    public ObjectPermissionSet getUserGroupPermissions()
            throws GuacamoleException {
        return new SimpleObjectPermissionSet(restrictedUserGroupDirectory.getIdentifiers());
    }

}
