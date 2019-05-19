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

package com.glyptodon.guacamole.auth.restrict.connection;

import java.util.Objects;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.UserContext;

/**
 * Uniquely identifies a connection or connection group. Unlike the string
 * identifier that may be used to uniquely identify a connection or connection
 * group from another object of the same type within the same UserContext, this
 * class uniquely identifies both connections and connection groups across
 * multiple AuthenticationProviders and UserContexts.
 */
public class GlobalConnectionIdentifier {

    /**
     * The types of objects that may be represented by a
     * GlobalConnectionIdentifier.
     */
    public enum Type {

        /**
         * A Connection object.
         */
        CONNECTION,

        /**
         * A ConnectionGroup object.
         */
        CONNECTION_GROUP,

    }

    /**
     * The AuthenticationProvider that originated the object represented by
     * this GlobalConnectionIdentifier.
     */
    private AuthenticationProvider authProvider;

    /**
     * The type of object represented by this GlobalConnectionIdentifier.
     */
    private Type type;

    /**
     * The string identifier which uniquely identifies this object within the
     * UserContext from which it was retrieved.
     */
    private String identifier;

    /**
     * Creates a new GlobalConnectionIdentifier which uniquely represents the
     * given ConnectionGroup.
     *
     * @param context
     *     The UserContext from which the given ConnectionGroup was retrieved.
     *
     * @param connectionGroup
     *     The ConnectionGroup that this GlobalConnectionIdentifier should
     *     represent.
     */
    public GlobalConnectionIdentifier(UserContext context, ConnectionGroup connectionGroup) {
        this.authProvider = context.getAuthenticationProvider();
        this.type = Type.CONNECTION_GROUP;
        this.identifier = connectionGroup.getIdentifier();
    }

    /**
     * Creates a new GlobalConnectionIdentifier which uniquely represents the
     * given Connection.
     *
     * @param context
     *     The UserContext from which the given Connection was retrieved.
     *
     * @param connection
     *     The Connection that this GlobalConnectionIdentifier should
     *     represent.
     */
    public GlobalConnectionIdentifier(UserContext context, Connection connection) {
        this.authProvider = context.getAuthenticationProvider();
        this.type = Type.CONNECTION;
        this.identifier = connection.getIdentifier();
    }

    @Override
    public int hashCode() {
        return Objects.hash(authProvider.getIdentifier(), type, identifier);
    }

    @Override
    public boolean equals(Object obj) {

        // This object is equal to itself
        if (this == obj)
            return true;

        // Compare only non-null objects of the same type (all others are
        // guaranteed to be not equal)
        if (obj == null || getClass() != obj.getClass())
            return false;

        GlobalConnectionIdentifier other = (GlobalConnectionIdentifier) obj;
        return authProvider == other.authProvider
            && type == other.type
            && identifier.equals(other.identifier);

    }

}
