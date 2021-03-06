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

import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import org.apache.guacamole.form.BooleanField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.net.auth.Attributes;

/**
 * A Restriction enforced by this extension. The association between a
 * restriction and a user group may be exposed through attributes. Each
 * restriction has a corresponding custom attribute that denotes whether the
 * restriction is in effect.
 */
public enum Restriction {

    /**
     * Disallows concurrent access to connections or connection groups that are
     * already in use, regardless of any restrictions enforced by other
     * extensions.
     */
    DISALLOW_CONCURRENT("addl-restrict-disallow-concurrent"),

    /**
     * Forces all connections to be read-only when accessed by the members of
     * the affected user group. When in effect, instructions sent to the
     * connection by affected group members will be dropped. Only the "sync"
     * instruction is allowed through.
     */
    FORCE_READ_ONLY("addl-restrict-force-read-only");

    /**
     * The string value used for the attribute associated with a restriction to
     * denote that the restriction has been enabled.
     */
    public static final String TRUTH_VALUE = "true";

    /**
     * The name of the custom attribute storing whether the restriction is
     * enabled for the associated user group.
     */
    private final String attributeName;

    /**
     * Creates a new Restriction which is exposed using the custom attribute
     * having the given name.
     *
     * @param attributeName
     *     The name of the attribute which exposes whether the restriction is
     *     enabled.
     */
    private Restriction(String attributeName) {
        this.attributeName = attributeName;
    }

    /**
     * Returns the name of the custom attribute storing whether the restriction
     * is enabled for the associated user group.
     *
     * @return
     *     The name of the attribute which exposes whether this restriction is
     *     enabled.
     */
    public String getAttributeName() {
        return attributeName;
    }

    /**
     * Creates a new map of attribute name/value pairs which exposes that the
     * restrictions in the given collection apply.
     *
     * @param restrictions
     *     The restrictions to convert into a new map of attribute name/value
     *     pairs.
     *
     * @return
     *     A new map of attribute name/value pairs which exposes that the given
     *     restrictions apply.
     */
    public static Map<String, String> asAttributeMap(Collection<Restriction> restrictions) {

        Map<String, String> attributes = new HashMap<>();
        for (Restriction restriction : restrictions)
            attributes.put(restriction.getAttributeName(), TRUTH_VALUE);

        return attributes;

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

    /**
     * Returns whether this restriction is in effect for the object associated
     * with the given attributes.
     *
     * @param object
     *     The object whose attributes should be used to determine whether this
     *     restriction applies.
     *
     * @return
     *     true of this restriction is enabled according to the given
     *     attributes, false otherwise.
     */
    public boolean isSet(Attributes object) {
        Map<String, String> attributes = object.getAttributes();
        return TRUTH_VALUE.equals(attributes.get(attributeName));
    }

    /**
     * Returns the set of restrictions which apply to the given object, as
     * dictated by associated attributes.
     *
     * @param object
     *     The object whose attributes should be used to determine the
     *     restrictions that apply.
     *
     * @return
     *     The set of restrictions which apply to the object according to its
     *     associated attributes.
     */
    public static EnumSet<Restriction> fromAttributes(Attributes object) {

        EnumSet<Restriction> restrictions = EnumSet.allOf(Restriction.class);

        // Remove all restrictions which are not enabled according to the
        // attributes associated with the given object
        restrictions.removeIf(restriction -> !restriction.isSet(object));

        return restrictions;

    }

}
