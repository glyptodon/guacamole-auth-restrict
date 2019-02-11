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

import java.util.Map;
import org.apache.guacamole.form.BooleanField;
import org.apache.guacamole.form.Field;

/**
 * A Restriction enforced by this extension. Restrictions may be associated
 * with users or user groups through attributes. Each restriction has a
 * corresponding custom attribute that controls whether the restriction is
 * enabled.
 */
public enum Restriction {

    /**
     * Forces all connections to be read-only when accessed by the affected
     * user or members of the affected user group. When in effect, instructions
     * sent to the connection by affected users or group members will be
     * dropped. Only the "sync" instruction is allowed through.
     */
    FORCE_READ_ONLY("addl-restrict-force-read-only");

    /**
     * The string value used for the attribute associated with a restriction to
     * denote that the restriction has been enabled.
     */
    public static final String TRUTH_VALUE = "true";

    /**
     * The name of the custom attribute storing whether the restriction is
     * enabled for the associated user or user group.
     */
    private final String attributeName;

    /**
     * Creates a new Restriction which is controlled by the custom attribute
     * having the given name.
     *
     * @param attributeName
     *     The name of the attribute which controls whether the restriction is
     *     enabled.
     */
    private Restriction(String attributeName) {
        this.attributeName = attributeName;
    }

    /**
     * Returns whether this restriction is in effect for the user or user group
     * associated with the given attributes.
     *
     * @param attributes
     *     A map of attribute name/value pairs retrieved from a user or user
     *     group.
     *
     * @return
     *     true of this restriction is enabled according to the given
     *     attributes, false otherwise.
     */
    public boolean isSet(Map<String, String> attributes) {
        return TRUTH_VALUE.equals(attributes.get(attributeName));
    }

    /**
     * Returns the name of the custom attribute storing whether the restriction
     * is enabled for the associated user or user group.
     *
     * @return
     *     The name of the attribute which controls whether this restriction is
     *     enabled.
     */
    public String getAttributeName() {
        return attributeName;
    }

    /**
     * Returns a Field which represents the attribute controlling whether this
     * restriction is enabled for a user or user group.
     *
     * @return
     *     A Field representing the attribute controlling whether this
     *     restriction is enabled.
     */
    public Field asField() {
        return new BooleanField(attributeName, TRUTH_VALUE);
    }

}
