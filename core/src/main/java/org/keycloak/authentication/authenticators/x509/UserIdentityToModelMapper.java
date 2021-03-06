/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.authentication.authenticators.x509;

import com.hsbc.unified.iam.core.constants.Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/30/2016
 */

public abstract class UserIdentityToModelMapper {
    @Autowired
    private KeycloakModelUtils keycloakModelUtils;
    @Autowired
    private UserProvider userProvider;

    public UserIdentityToModelMapper getUsernameOrEmailMapper() {
        return new UsernameOrEmailMapper();
    }

    public UserIdentityToModelMapper getUserIdentityToCustomAttributeMapper(String attributeName) {
        return new UserIdentityToCustomAttributeMapper(attributeName);
    }

    public abstract UserModel find(AuthenticationFlowContext context, Object userIdentity) throws Exception;

    public class UsernameOrEmailMapper extends UserIdentityToModelMapper {
        @Override
        public UserModel find(AuthenticationFlowContext context, Object userIdentity) throws Exception {
            return keycloakModelUtils.findUserByNameOrEmail(context.getRealm(), userIdentity.toString().trim());
        }
    }

    public class UserIdentityToCustomAttributeMapper extends UserIdentityToModelMapper {
        private List<String> _customAttributes;

        UserIdentityToCustomAttributeMapper(String customAttributes) {
            _customAttributes = Arrays.asList(Constants.CFG_DELIMITER_PATTERN.split(customAttributes));
        }

        @Override
        public UserModel find(AuthenticationFlowContext context, Object userIdentity) throws Exception {
            List<String> userIdentityValues = Arrays.asList(Constants.CFG_DELIMITER_PATTERN.split(userIdentity.toString()));

            if (_customAttributes.isEmpty() || userIdentityValues.isEmpty() || (_customAttributes.size() != userIdentityValues.size())) {
                return null;
            }
            List<UserModel> users = userProvider.searchForUserByUserAttribute(_customAttributes.get(0), userIdentityValues.get(0), context.getRealm());

            for (int i = 1; i < _customAttributes.size(); ++i) {
                String customAttribute = _customAttributes.get(i);
                String userIdentityValue = userIdentityValues.get(i);

                users = users.stream().filter(user -> user.getFirstAttribute(customAttribute).equals(userIdentityValue)).collect(Collectors.toList());
            }
            if (users != null && users.size() > 1) {
                throw new ModelDuplicateException();
            }
            return users != null && users.size() == 1 ? users.get(0) : null;
        }
    }
}
