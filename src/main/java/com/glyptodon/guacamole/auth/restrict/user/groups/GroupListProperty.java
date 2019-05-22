/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* NOTE: This class was derived from the StringListProperty class defined
   within the upstream guacamole-auth-ldap extension. */

package com.glyptodon.guacamole.auth.restrict.user.groups;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.properties.GuacamoleProperty;

/**
 * A property whose value is a comma-delimited list of group names (Strings).
 * Whitespace preceding any name is ignored, however whitespace after a name is
 * interpreted as part of the name.
 */
public abstract class GroupListProperty implements GuacamoleProperty<List<String>> {

    /**
     * Pattern which matches the delimiters between values.
     */
    private static final Pattern DELIMITER = Pattern.compile(",\\s*");

    @Override
    public List<String> parseValue(String values) throws GuacamoleException {

        // If no property provided, return null.
        if (values == null)
            return null;

        // Split string into a list of individual values
        List<String> stringValues = Arrays.asList(DELIMITER.split(values));
        if (stringValues.isEmpty())
            return null;

        return stringValues;

    }

}
