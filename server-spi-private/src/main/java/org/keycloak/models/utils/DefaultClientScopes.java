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

package org.keycloak.models.utils;

import org.keycloak.OAuth2Constants;
import org.keycloak.models.*;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.provider.ProviderFactory;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DefaultClientScopes {

    /**
     * @param session
     * @param realm
     * @param addScopesToExistingClients true when creating new realm. False when migrating from previous version
     */
    public static void createDefaultClientScopes(KeycloakSession session, RealmModel realm, boolean addScopesToExistingClients) {
        List<ProviderFactory> loginProtocolFactories = session.getSessionFactory().getProviderFactories(LoginProtocol.class);
        for (ProviderFactory factory : loginProtocolFactories) {
            LoginProtocolFactory lpf = (LoginProtocolFactory) factory;
            lpf.createDefaultClientScopes(realm, addScopesToExistingClients);
        }
    }


    // Asumption is that newRealm and offlineRole are not null AND offline_access clientScope doesn't yet exists in the realm. Caller of this method is supposed to ensure that.
    public static void createOfflineAccessClientScope(RealmModel newRealm, RoleModel offlineRole) {
        ClientScopeModel offlineAccessScope = newRealm.addClientScope(OAuth2Constants.OFFLINE_ACCESS);
        offlineAccessScope.setDescription("OpenID Connect built-in scope: offline_access");
        offlineAccessScope.setDisplayOnConsentScreen(true);
        offlineAccessScope.setConsentScreenText(Constants.OFFLINE_ACCESS_SCOPE_CONSENT_TEXT);
        offlineAccessScope.setProtocol("openid-connect");
        offlineAccessScope.addScopeMapping(offlineRole);

        // Optional scope. Needs to be requested by scope parameter
        newRealm.addDefaultClientScope(offlineAccessScope, false);
    }
}
