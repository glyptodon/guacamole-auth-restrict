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

package com.glyptodon.guacamole.auth.restrict;

import com.glyptodon.guacamole.auth.restrict.connection.ConnectionManager;
import com.glyptodon.guacamole.auth.restrict.user.RestrictedExternalUserContext;
import com.glyptodon.guacamole.auth.restrict.user.RestrictedUserContext;
import com.glyptodon.guacamole.auth.restrict.user.groups.RestrictedUserGroupDirectory;
import com.google.common.collect.Sets;
import java.util.Set;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

/**
 * AuthenticationProvider implementation which enforces restrictions defined by
 * specific user groups. The additional restrictions applicable to the groups
 * defined by this extension are exposed in a read-only way through custom
 * attributes.
 */
public class RestrictedAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * The Guacamole server environment.
     */
    private final Environment environment;

    /**
     * The directory of all user groups defined by the
     * "guacamole-auth-restrict" extension.
     */
    private final RestrictedUserGroupDirectory restrictedUserGroupDirectory;

    /**
     * Singleton instance of ConnectionManager, to be used to track connection
     * usage across all UserContexts simultaneously.
     */
    private final ConnectionManager manager = new ConnectionManager();

    /**
     * Creates a new RestrictedAuthenticationProvider which reads all
     * configuration information from the local Guacamole server environment
     * (GUACAMOLE_HOME/guacamole.properties).
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be read.
     */
    public RestrictedAuthenticationProvider() throws GuacamoleException {
        this.environment = new LocalEnvironment();
        this.restrictedUserGroupDirectory = new RestrictedUserGroupDirectory(environment);
    }

    @Override
    public String getIdentifier() {
        return "addl-restrict";
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {
        return new RestrictedUserContext(this, authenticatedUser, restrictedUserGroupDirectory);
    }

    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {

        // Include restrictions from effective groups (defined by the extension
        // authenticating the user) and from the user object (defined by the
        // extension associated with the UserContext being decorated)
        Set<Restriction> restrictions = Sets.union(
            restrictedUserGroupDirectory.getRestrictions(authenticatedUser),
            Restriction.fromAttributes(context.self())
        );

        return new RestrictedExternalUserContext(manager, restrictions, context);

    }

}
