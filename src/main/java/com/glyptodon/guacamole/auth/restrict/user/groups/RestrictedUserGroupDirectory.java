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

import com.glyptodon.guacamole.auth.restrict.Restriction;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.UserGroup;
import org.apache.guacamole.net.auth.simple.SimpleDirectory;

/**
 * Directory of all user groups defined by the "guacamole-auth-restrict"
 * extension.
 */
public class RestrictedUserGroupDirectory extends SimpleDirectory<UserGroup> {

    /**
     * The Guacamole property controlling the group whose members should be
     * restricted to read-only access.
     */
    private static final GroupListProperty READ_ONLY_GROUPS = new GroupListProperty() {

        @Override
        public String getName() {
            return "read-only-groups";
        }

    };

    /**
     * Returns a collection of all user groups that should be exposed by this
     * directory. These groups are dictated by properties within
     * guacamole.properties.
     *
     * @param environment
     *     The Environment to retrieve configuration information from.
     *
     * @return
     *     A collection of all user groups that should be exposed by this
     *     directory, as defined by guacamole.properties.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be read, or an error occurs parsing
     *     configuration options within guacamole.properties.
     */
    private static Collection<UserGroup> getPredefinedUserGroups(Environment environment)
            throws GuacamoleException {

        Multimap<String, Restriction> groupRestrictions = HashMultimap.create();

        // Add read-only restriction for all specified groups
        for (String identifier : environment.getProperty(READ_ONLY_GROUPS, Collections.emptyList()))
            groupRestrictions.put(identifier, Restriction.FORCE_READ_ONLY);

        // Produce overall collection of defined groups, including any associated restrictions
        return groupRestrictions.keySet().stream()
                .map(identifier -> new RestrictedUserGroup(identifier, groupRestrictions.get(identifier)))
                .collect(Collectors.toList());

    }

    /**
     * Creates a new RestrictedUserGroupDirectory which uses the given
     * Environment to retrieve any relevant configuration information. The
     * following properties are currently defined:
     *
     *     "read-only-groups" - The names of all group which should be
     *         restricted to read-only access. By default, no groups are
     *         restricted.
     *
     * @param environment
     *     The Environment to retrieve configuration information from.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be read, or an error occurs parsing
     *     configuration options within guacamole.properties.
     */
    public RestrictedUserGroupDirectory(Environment environment) throws GuacamoleException {
        super(getPredefinedUserGroups(environment));
    }

    /**
     * Retrieves all restrictions which apply to the given AuthenticatedUser
     * according to their effective group memberships.
     *
     * @param user
     *     The AuthenticatedUser to retrieve the applicable restrictions of.
     *
     * @return
     *     A set of all restrictions that apply to the given AuthenticatedUser.
     *
     * @throws GuacamoleException
     *     If the restrictions that apply to the given AuthenticatedUser cannot
     *     be determined due to an error.
     */
    public Set<Restriction> getRestrictions(AuthenticatedUser user)
            throws GuacamoleException {

        // Retrieve all effective user groups
        Collection<UserGroup> groups = getAll(user.getEffectiveUserGroups());

        // Add restrictions of all effective user groups
        EnumSet<Restriction> restrictions = EnumSet.noneOf(Restriction.class);
        for (UserGroup group : groups)
            restrictions.addAll(((RestrictedUserGroup) group).getRestrictions());

        return restrictions;

    }

}
