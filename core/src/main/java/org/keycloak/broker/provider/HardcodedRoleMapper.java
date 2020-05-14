/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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
 */

package org.keycloak.broker.provider;

import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component("HardcodedRoleMapper")
@ProviderFactory(id = "oidc-hardcoded-role-idp-mapper", providerClasses = IdentityProviderMapper.class)
public class HardcodedRoleMapper extends AbstractIdentityProviderMapper {
    public static final String[] COMPATIBLE_PROVIDERS = {ANY_PROVIDER};
    public static final String PROVIDER_ID = "oidc-hardcoded-role-idp-mapper";
    protected static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ConfigConstants.ROLE);
        property.setLabel("Role");
        property.setHelpText("Role to grant to user.  Click 'Select Role' button to browse roles, or just type it in the textbox.  To reference an application role the syntax is appname.approle, i.e. myapp.myrole");
        property.setType(ProviderConfigProperty.ROLE_TYPE);
        configProperties.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Hardcoded Role";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String roleName = mapperModel.getConfig().get(ConfigConstants.ROLE);
        RoleModel role = KeycloakModelUtils.getRoleFromString(realm, roleName);
        if (role == null) throw new IdentityBrokerException("Unable to find role: " + roleName);
        user.grantRole(role);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

    }

    @Override
    public String getHelpText() {
        return "When user is imported from provider, hardcode a role mapping for it.";
    }
}
