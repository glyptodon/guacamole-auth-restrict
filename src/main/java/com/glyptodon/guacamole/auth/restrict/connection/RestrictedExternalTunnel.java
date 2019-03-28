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

import java.util.Set;
import com.glyptodon.guacamole.auth.restrict.Restriction;
import com.glyptodon.guacamole.auth.restrict.user.RestrictedExternalUserContext;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.io.GuacamoleWriter;
import org.apache.guacamole.net.DelegatingGuacamoleTunnel;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.FilteredGuacamoleWriter;
import org.apache.guacamole.protocol.GuacamoleInstruction;

/**
 * GuacamoleTunnel implementation which enforces the restrictions affecting
 * the user accessing the tunnel.
 */
public class RestrictedExternalTunnel extends DelegatingGuacamoleTunnel {

    /**
     * The set of restrictions affecting the user accessing this tunnel.
     */
    private final Set<Restriction> restrictions;

    /**
     * Creates a new RestrictedTunnel which wraps the given tunnel, enforcing
     * the restrictions that apply to the user associated with the given
     * UserContext.
     *
     * @param userContext
     *     The UserContext of the user accessing the tunnel.
     *
     * @param tunnel
     *     The tunnel that the user is attempting to access.
     */
    public RestrictedExternalTunnel(RestrictedExternalUserContext userContext,
            GuacamoleTunnel tunnel) {
        super(tunnel);
        this.restrictions = userContext.getRestrictions();
    }

    /**
     * Returns whether the user accessing this tunnel can write the given
     * instruction.
     *
     * @param instruction
     *     The instruction received from the user accessing this tunnel.
     *
     * @return
     *     true if the user has permission to write the given instruction,
     *     false if some restriction prohibits the instruction from being
     *     written.
     */
    private boolean canWrite(GuacamoleInstruction instruction) {

        // Always allow "sync"
        String opcode = instruction.getOpcode();
        if ("sync".equals(opcode))
            return true;

        // Otherwise, allow instructions to pass through only if the user is
        // not subject to read-only restrictions
        return !restrictions.contains(Restriction.FORCE_READ_ONLY);
        
    }

    @Override
    public GuacamoleWriter acquireWriter() {

        // Filter written instructions according to any active restrictions
        return new FilteredGuacamoleWriter(super.acquireWriter(),
                instruction -> canWrite(instruction) ? instruction : null);

    }

    @Override
    public GuacamoleReader acquireReader() {

        // Allow receipt of any instructions sent by guacd
        return super.acquireReader();

    }

}
