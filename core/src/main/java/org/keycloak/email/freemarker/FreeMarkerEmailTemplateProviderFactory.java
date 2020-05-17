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

package org.keycloak.email.freemarker;

import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.EmailTemplateProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.theme.FreeMarkerUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("FreeMarkerEmailTemplateProviderFactory")
@ProviderFactory(id = "freemarker", providerClasses = EmailTemplateProvider.class)
public class FreeMarkerEmailTemplateProviderFactory implements EmailTemplateProviderFactory {
    @Autowired
    private FreeMarkerUtil freeMarker;

    @Override
    public EmailTemplateProvider create(KeycloakSession session) {
        return new FreeMarkerEmailTemplateProvider(session, freeMarker);
    }

    @PostConstruct
    public void destroy() {
        freeMarker = null;
    }

    @Override
    public String getId() {
        return "freemarker";
    }
}