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

import java.util.Map;
import org.apache.guacamole.GuacamoleException;
import com.glyptodon.guacamole.auth.restrict.user.RestrictedExternalUserContext;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.ConnectionGroup;
import org.apache.guacamole.net.auth.DelegatingConnectionGroup;
import org.apache.guacamole.protocol.GuacamoleClientInformation;

/**
 * ConnectionGroup implementation which enforces the restrictions affecting the
 * user accessing the connection group.
 */
public class RestrictedExternalConnectionGroup extends DelegatingConnectionGroup {

    /**
     * The UserContext of the user accessing this object.
     */
    private final RestrictedExternalUserContext userContext;

    /**
     * Creates a new RestrictedConnectionGroup which wraps the given connection
     * group, enforcing the restrictions that apply to the user associated with
     * the given UserContext.
     *
     * @param userContext
     *     The UserContext of the user accessing the connection group.
     *
     * @param connectionGroup
     *     The connection group that the user is attempting to access.
     */
    public RestrictedExternalConnectionGroup(RestrictedExternalUserContext userContext,
            ConnectionGroup connectionGroup) {
        super(connectionGroup);
        this.userContext = userContext;
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {
        return new RestrictedExternalTunnel(userContext, super.connect(info, tokens));
    }

    /**
     * Returns the original ConnectionGroup wrapped by this
     * RestrictedConnectionGroup. The returned ConnectionGroup will not be
     * affected by the restrictions otherwise enforced by this extension.
     *
     * @return
     *     The original ConnectionGroup wrapped by this
     *     RestrictedConnectionGroup.
     */
    public ConnectionGroup getUnrestrictedConnectionGroup() {
        return getDelegateConnectionGroup();
    }

}
