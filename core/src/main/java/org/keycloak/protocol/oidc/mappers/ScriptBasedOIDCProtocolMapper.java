/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc.mappers;

import org.keycloak.common.Profile;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.representations.IDToken;
import org.keycloak.scripting.EvaluatableScriptAdapter;
import org.keycloak.scripting.ScriptCompilationException;
import org.keycloak.scripting.ScriptingProvider;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * OIDC {@link org.keycloak.protocol.ProtocolMapper} that uses a provided JavaScript fragment to compute the token claim value.
 *
 * @author <a href="mailto:thomas.darimont@gmail.com">Thomas Darimont</a>
 */
@Component("OIDCScriptBasedOIDCProtocolMapper")
@ProviderFactory(id = "oidc-script-based-protocol-mapper", providerClasses = ProtocolMapper.class)
public class ScriptBasedOIDCProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper,
        EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "oidc-script-based-protocol-mapper";

    private static final Logger LOGGER = LoggerFactory.getLogger(ScriptBasedOIDCProtocolMapper.class);

    private static final String SCRIPT = "script";

    private static final List<ProviderConfigProperty> configProperties;

    static {

        configProperties = ProviderConfigurationBuilder.create()
                .property()
                .name(SCRIPT)
                .type(ProviderConfigProperty.SCRIPT_TYPE)
                .label("Script")
                .helpText(
                        "Script to compute the claim value. \n" + //
                                " Available variables: \n" + //
                                " 'user' - the current user.\n" + //
                                " 'realm' - the current realm.\n" + //
                                " 'token' - the current token.\n" + //
                                " 'userSession' - the current userSession.\n" + //
                                " 'keycloakSession' - the current keycloakSession.\n" //
                )
                .defaultValue("/**\n" + //
                        " * Available variables: \n" + //
                        " * user - the current user\n" + //
                        " * realm - the current realm\n" + //
                        " * token - the current token\n" + //
                        " * userSession - the current userSession\n" + //
                        " * keycloakSession - the current keycloakSession\n" + //
                        " */\n\n\n//insert your code here..." //
                )
                .add()
                .property()
                .name(ProtocolMapperUtils.MULTIVALUED)
                .label(ProtocolMapperUtils.MULTIVALUED_LABEL)
                .helpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT)
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue(false)
                .add()
                .build();

        OIDCAttributeMapperHelper.addAttributeConfig(configProperties, UserPropertyMapper.class);
    }

    public static ProtocolMapperModel create(String name,
                                             String userAttribute,
                                             String tokenClaimName, String claimType,
                                             boolean accessToken, boolean idToken, String script, boolean multiValued) {
        ProtocolMapperModel mapper = OIDCAttributeMapperHelper.createClaimMapper(name, userAttribute,
                tokenClaimName, claimType,
                accessToken, idToken,
                PROVIDER_ID);

        mapper.getConfig().put(SCRIPT, script);
        mapper.getConfig().put(ProtocolMapperUtils.MULTIVALUED, String.valueOf(multiValued));

        return mapper;
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Script Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Evaluates a JavaScript function to produce a token claim based on context information.";
    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.SCRIPTS) && Profile.isFeatureEnabled(Profile.Feature.UPLOAD_SCRIPTS);
    }

    @Override
    public int getPriority() {
        return ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER;
    }

    @Autowired
    private ScriptingProvider scriptingProvider;

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        String scriptSource = getScriptCode(mappingModel);
        RealmModel realm = userSession.getRealm();

        ScriptModel scriptModel = scriptingProvider.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, "token-mapper-script_" + mappingModel.getName(), scriptSource, null);

        EvaluatableScriptAdapter script = scriptingProvider.prepareEvaluatableScript(scriptModel);

        Object claimValue;
        try {
            claimValue = script.eval((bindings) -> {
                bindings.put("user", user);
                bindings.put("realm", realm);
                bindings.put("token", token);
                bindings.put("userSession", userSession);
                bindings.put("keycloakSession", keycloakSession);
            });
        } catch (Exception ex) {
            LOGGER.error("Error during execution of ProtocolMapper script", ex);
            claimValue = null;
        }

        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
    }

    @Override
    public void validateConfig(RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {

        String scriptCode = getScriptCode(mapperModel);
        if (scriptCode == null) {
            return;
        }

        ScriptModel scriptModel = scriptingProvider.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, mapperModel.getName() + "-script", scriptCode, "");

        try {
            scriptingProvider.prepareEvaluatableScript(scriptModel);
        } catch (ScriptCompilationException ex) {
            throw new ProtocolMapperConfigException("error", "{}", ex.getMessage());
        }
    }

    protected String getScriptCode(ProtocolMapperModel mapperModel) {
        return mapperModel.getConfig().get(SCRIPT);
    }
}
