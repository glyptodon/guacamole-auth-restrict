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
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedExternalConnection;
import com.glyptodon.guacamole.auth.restrict.connection.RestrictedExternalConnectionGroup;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.UserContext;

/**
 * UserContext implementation which enforces additional restrictions on users
 * and the members of user groups based on custom attributes.
 */
public class RestrictedExternalUserContext extends DelegatingUserContext
        implements Restricted {

    /**
     * The restrictions that apply to the wrapped UserContext.
     */
    private final Set<Restriction> restrictions;

    /**
     * Creates a new RestrictedUserContext which wraps the given UserContext,
     * applying the given restrictions.
     *
     * @param restrictions
     *     The restrictions to apply to the given UserContext.
     *
     * @param userContext
     *     The UserContext restrict access to.
     */
    public RestrictedExternalUserContext(Set<Restriction> restrictions,
            UserContext userContext) {
        super(userContext);
        this.restrictions = restrictions;
    }

    @Override
    public Set<Restriction> getRestrictions() {
        return restrictions;
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

}
