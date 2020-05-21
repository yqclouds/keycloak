/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.locale;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.storage.ReadOnlyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.UriInfo;

public class DefaultLocaleUpdaterProvider implements LocaleUpdaterProvider {

    private static final Logger LOG = LoggerFactory.getLogger(LocaleSelectorProvider.class);

    @Override
    public void updateUsersLocale(UserModel user, String locale) {
        if (!locale.equals(user.getFirstAttribute("locale"))) {
            try {
                user.setSingleAttribute(UserModel.LOCALE, locale);
                updateLocaleCookie(locale);
            } catch (ReadOnlyException e) {
                LOG.debug("Attempt to store 'locale' attribute to read only user model. Ignoring exception", e);
            }
        }
        LOG.debug("Setting locale for user {} to {}", user.getUsername(), locale);
    }

    @Autowired
    private KeycloakContext keycloakContext;

    @Override
    public void updateLocaleCookie(String locale) {
        RealmModel realm = keycloakContext.getRealm();
        UriInfo uriInfo = keycloakContext.getUri();

        boolean secure = realm.getSslRequired().isRequired(uriInfo.getRequestUri().getHost());
        CookieHelper.addCookie(LocaleSelectorProvider.LOCALE_COOKIE, locale, AuthenticationManager.getRealmCookiePath(realm, uriInfo), null, null, -1, secure, true);
        LOG.debug("Updating locale cookie to {}", locale);
    }

    @Override
    public void expireLocaleCookie() {
        RealmModel realm = keycloakContext.getRealm();
        UriInfo uriInfo = keycloakContext.getUri();

        boolean secure = realm.getSslRequired().isRequired(keycloakContext.getConnection());
        CookieHelper.addCookie(LocaleSelectorProvider.LOCALE_COOKIE, "", AuthenticationManager.getRealmCookiePath(realm, uriInfo), null, "Expiring cookie", 0, secure, true);
    }

    @Override
    public void close() {
    }

}
