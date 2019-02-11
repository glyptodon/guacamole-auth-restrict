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

import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.UserContext;

/**
 * Factory for creating UserContext instances which enforce additional
 * restrictions on users and the members of user groups based on custom
 * attributes.
 */
public interface RestrictedUserContextFactory {

    /**
     * Returns a new instance of a UserContext implementation which
     * automatically enforces additional restrictions on users and members of
     * user groups based on custom attributes. If the current user has
     * administrative permissions, these custom attributes will also be made
     * available for modification on the objects that the current user has
     * permission to administer.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser representing the user associated with the
     *     given UserContext (the current user).
     *
     * @param userContext
     *     The UserContext instance to protect access to.
     *
     * @return
     *     A new UserContext instance which automatically enforces additional
     *     restrictions based on custom attributes.
     */
    UserContext create(AuthenticatedUser authenticatedUser,
            UserContext userContext);

}
