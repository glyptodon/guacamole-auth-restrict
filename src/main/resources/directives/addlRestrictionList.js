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

/**
 * Directive which displays a list of all restrictions enforced by the
 * "guacamole-auth-restrict" extension for a particular user group defined by
 * that extension.
 */
angular.module('manage').directive('addlRestrictionList', ['$injector',
    function addlRestrictionList($injector) {

    // Required services
    var translationStringService = $injector.get('translationStringService');

    var directive = {

        restrict    : 'E',
        replace     : true,
        templateUrl : 'app/ext/addl-restrict/templates/addlRestrictionList.html',

        scope : {

            /**
             * The user group currently being displayed.
             *
             * @type UserGroup
             */
            userGroup : '='

        }

    };

    directive.controller = ['$scope', function addlRestrictionListController($scope) {

        /**
         * The names of all restriction attributes associated with the current
         * user group, in ascending alphabetical order.
         *
         * @type String[]
         */
        $scope.restrictions = [];

        /**
         * Returns translation string which defines the human-readable name of
         * the restriction represented by the given attribute.
         *
         * @param {String} attribute
         *     The name of the attribute.
         *
         * @returns {String}
         *     The translation string which defines the human-readable name of
         *     the restriction represented by the given attribute.
         */
        $scope.getRestrictionName = function getRestrictionName(attribute) {
            return 'MANAGE_USER_GROUP.' + translationStringService.canonicalize('NAME_' + attribute);
        };

        /**
         * Returns translation string which defines a human-readable
         * description for the restriction represented by the given attribute.
         *
         * @param {String} attribute
         *     The name of the attribute.
         *
         * @returns {String}
         *     The translation string which defines a human-readable
         *     description for the restriction represented by the given
         *     attribute.
         */
        $scope.getRestrictionDescription = function getRestrictionDescription(attribute) {
            return 'MANAGE_USER_GROUP.' + translationStringService.canonicalize('INFO_' + attribute);
        };

        // Keep restrictions list synchronized with the selected user group
        $scope.$watch('userGroup', function userGroupChanged(userGroup) {

            // Reset current set of restrictions
            $scope.restrictions = [];

            // If no user group is set, there are no restrictions
            if (!userGroup)
                return;

            // Filter the set of user group attributes, producing a list of
            // only those attributes associated with "guacamole-auth-restrict"
            // restrictions
            angular.forEach(userGroup.attributes, function addRestrictions(value, attribute) {
                if (/^addl-restrict-/.test(attribute) && value === 'true')
                    $scope.restrictions.push(attribute);
            });

            // Maintain sorted order
            $scope.restrictions.sort();

        });

    }];

    return directive;

}]);
