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

package com.glyptodon.guacamole.auth.restrict.user.groups;

import com.glyptodon.guacamole.auth.restrict.Restricted;
import com.glyptodon.guacamole.auth.restrict.Restriction;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.apache.guacamole.net.auth.simple.SimpleUserGroup;

/**
 * A user group with an associated set of restrictions that should apply to
 * members of the group.
 */
public class RestrictedUserGroup extends SimpleUserGroup
        implements Restricted {

    /**
     * The set of restrictions that should apply to members of this group.
     */
    private final Set<Restriction> restrictions;

    /**
     * The map of attribute name/value pairs that corresponds to the
     * restrictions applying to members of this group.
     */
    private final Map<String, String> attributes;

    /**
     * Creates a new RestrictedUserGroup having the given unique identifier and
     * associated restrictions.
     *
     * @param identifier
     *     The unique identifier to assign to this RestrictedUserGroup.
     *
     * @param restrictions
     *     The restrictions that apply to members of this group.
     */
    public RestrictedUserGroup(String identifier, Collection<Restriction> restrictions) {
        super(identifier);
        this.restrictions = restrictions.isEmpty() ? Collections.emptySet() : Collections.unmodifiableSet(EnumSet.copyOf(restrictions));
        this.attributes = Collections.unmodifiableMap(Restriction.asAttributeMap(restrictions));
    }

    /**
     * Creates a new RestrictedUserGroup having the given unique identifier and
     * associated restrictions.
     *
     * @param identifier
     *     The unique identifier to assign to this RestrictedUserGroup.
     *
     * @param restrictions
     *     The restrictions that apply to members of this group.
     */
    public RestrictedUserGroup(String identifier, Restriction... restrictions) {
        this(identifier, Arrays.asList(restrictions));
    }

    @Override
    public Set<Restriction> getRestrictions() {
        return restrictions;
    }

    @Override
    public Map<String, String> getAttributes() {
        return attributes;
    }

}
