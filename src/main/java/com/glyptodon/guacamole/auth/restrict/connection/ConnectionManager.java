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

import com.glyptodon.guacamole.auth.restrict.Restriction;
import com.glyptodon.guacamole.auth.restrict.user.RestrictedExternalUserContext;
import com.google.common.collect.ConcurrentHashMultiset;
import java.util.Map;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleResourceConflictException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.Connectable;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * Tracks active connections, automatically enforcing concurrent access
 * restrictions. Connections and connection groups may both be tracked. Tracked
 * objects need not come from the same UserContext nor from the same
 * AuthenticationProvider.
 */
public class ConnectionManager {

    /**
     * All active connections.
     */
    private final ConcurrentHashMultiset<GlobalConnectionIdentifier> activeConnections = ConcurrentHashMultiset.create();

    /**
     * Attempts to marks the connectable object associated with the given
     * identifier as in use. If the object is already in use and concurrent use
     * of the object is prohibited, this operation will fail. If successful,
     * the object must eventually be unmarked as in use through a call to
     * release().
     *
     * @param identifier
     *     The identifier which uniquely identifies the object being connected
     *     to.
     *
     * @param concurrent
     *     Whether concurrent access to the object having the given identifier
     *     should be allowed.
     *
     * @return
     *     true if the object having the given identifier was successfully
     *     marked as in use, false if the operation failed due to concurrent
     *     access restrictions.
     */
    private boolean acquire(GlobalConnectionIdentifier identifier, boolean concurrent) {

        // Increase connection usage by one
        activeConnections.add(identifier);

        // Fail acquisition if concurrent access is prohibited and we are not
        // the only user of this connection
        if (!concurrent && activeConnections.count(identifier) != 1) {
            activeConnections.remove(identifier);
            return false;
        }

        // Acquisition succeeded - connection is allowed
        return true;

    }

    /**
     * Unmarks the connectable object associated with the given identifier as
     * in use. This function MUST be called exactly once for every successful
     * call to acquire() and MUST NOT be called for any acquire() call that
     * failed.
     *
     * @param identifier
     *     The identifier which uniquely identifies the object which is no
     *     longer in use.
     */
    private void release(GlobalConnectionIdentifier identifier) {
        activeConnections.remove(identifier);
    }

    /**
     * Returns whether the user associated with the given UserContext is
     * allowed to establish concurrent connections to a connectable object that
     * is already in use.
     *
     * @param userContext
     *     The UserContext associated with the user to check.
     *
     * @return
     *     true if the user associated with the given UserContext is allowed to
     *     establish concurrent connections, false otherwise.
     */
    private boolean canConnectConcurrently(RestrictedExternalUserContext userContext) {
        return !userContext.getRestrictions().contains(Restriction.DISALLOW_CONCURRENT);
    }

    /**
     * Attempts to connect to the given connectable object, tracking concurrent
     * usage of that object. Concurrent access restrictions which apply to the
     * user connecting to the object are automatically enforced.
     *
     * @param userContext
     *     The UserContext associated with the user attempting to connect.
     *
     * @param identifier
     *     A GlobalConnectionIdentifier which uniquely identifies the
     *     connectable object that the user is connecting to.
     *
     * @param connectable
     *     The object that the user is connecting to.
     *
     * @param info
     *     The GuacamoleClientInformation describing the connecting client.
     *
     * @param tokens
     *     A Map containing the token names and corresponding values to be
     *     applied as parameter tokens when establishing the connection.
     *
     * @return
     *     The GuacamoleTunnel resulting from establishing the connection.
     *
     * @throws GuacamoleException
     *     If the connection cannot be established.
     */
    private GuacamoleTunnel connect(RestrictedExternalUserContext userContext,
            GlobalConnectionIdentifier identifier, Connectable connectable,
            GuacamoleClientInformation info, Map<String, String> tokens)
            throws GuacamoleException {

        // Track new connection, disallowing access if concurrent access
        // restrictions dictate that the connection should not be allowed
        if (!acquire(identifier, canConnectConcurrently(userContext)))
            throw new GuacamoleResourceConflictException("Concurrent access "
                    + "to this connection is not allowed for the current "
                    + "user.");

        try {
            return new RestrictedExternalTunnel(userContext, connectable.connect(info, tokens)) {

                @Override
                public void close() throws GuacamoleException {

                    super.close();

                    // Automatically release tracked connection when connection
                    // is closed
                    release(identifier);

                }

            };
        }
        catch (GuacamoleException | RuntimeException | Error e) {

            // Automatically release tracked connection if an error prevents
            // the connection from starting
            release(identifier);
            throw e;

        }

    }

    /**
     * Attempts to connect to the given connection, tracking concurrent usage
     * of that connection. Concurrent access restrictions which apply to the
     * connecting user are automatically enforced.
     *
     * @param userContext
     *     The UserContext associated with the user attempting to connect.
     *
     * @param connection
     *     The connection that the user is connecting to.
     *
     * @param info
     *     The GuacamoleClientInformation describing the connecting client.
     *
     * @param tokens
     *     A Map containing the token names and corresponding values to be
     *     applied as parameter tokens when establishing the connection.
     *
     * @return
     *     The GuacamoleTunnel resulting from establishing the connection.
     *
     * @throws GuacamoleException
     *     If the connection cannot be established.
     */
    public GuacamoleTunnel connect(RestrictedExternalUserContext userContext,
            Connection connection, GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {

        GlobalConnectionIdentifier identifier = new GlobalConnectionIdentifier(userContext, connection);
        return connect(userContext, identifier, connection, info, tokens);

    }

    /**
     * Attempts to connect to the given connection group, tracking concurrent
     * usage of that group. Concurrent access restrictions which apply to the
     * connecting user are automatically enforced.
     *
     * @param userContext
     *     The UserContext associated with the user attempting to connect.
     *
     * @param connectionGroup
     *     The connection group that the user is connecting to.
     *
     * @param info
     *     The GuacamoleClientInformation describing the connecting client.
     *
     * @param tokens
     *     A Map containing the token names and corresponding values to be
     *     applied as parameter tokens when establishing the connection.
     *
     * @return
     *     The GuacamoleTunnel resulting from establishing the connection.
     *
     * @throws GuacamoleException
     *     If the connection cannot be established.
     */
    public GuacamoleTunnel connect(RestrictedExternalUserContext userContext,
            ConnectionGroup connectionGroup, GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {

        GlobalConnectionIdentifier identifier = new GlobalConnectionIdentifier(userContext, connectionGroup);
        return connect(userContext, identifier, connectionGroup, info, tokens);

    }

}
