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

package org.keycloak.forms.login.freemarker;

import freemarker.template.TemplateMethodModelEx;
import freemarker.template.TemplateModelException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

/**
 *
 */
public class AuthenticatorConfiguredMethod implements TemplateMethodModelEx {
    private final RealmModel realm;
    private final UserModel user;

    public AuthenticatorConfiguredMethod(RealmModel realm, UserModel user) {
        this.realm = realm;
        this.user = user;
    }

    @Autowired
    private Map<String, Authenticator> authenticators;

    @Override
    public Object exec(List list) throws TemplateModelException {
        String providerId = list.get(0).toString();
        Authenticator authenticator = authenticators.get(providerId);
        return authenticator.configuredFor(realm, user);
    }
}
