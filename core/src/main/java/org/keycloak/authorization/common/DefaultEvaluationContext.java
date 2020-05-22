/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.common;

import org.keycloak.authorization.attribute.Attributes;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Map.Entry;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultEvaluationContext implements EvaluationContext {

    protected final Identity identity;
    private final Map<String, List<String>> claims;
    private Attributes attributes;

    @Autowired
    private KeycloakContext keycloakContext;

    public DefaultEvaluationContext(Identity identity) {
        this(identity, null);
    }

    public DefaultEvaluationContext(Identity identity, Map<String, List<String>> claims) {
        this.identity = identity;
        this.claims = claims;
    }

    @Override
    public Identity getIdentity() {
        return identity;
    }

    protected Map<String, Collection<String>> getBaseAttributes() {
        Map<String, Collection<String>> attributes = new HashMap<>();

        attributes.put("kc.time.date_time", Arrays.asList(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())));
        attributes.put("kc.client.network.ip_address", Arrays.asList(keycloakContext.getConnection().getRemoteAddr()));
        attributes.put("kc.client.network.host", Arrays.asList(keycloakContext.getConnection().getRemoteHost()));

        List<String> userAgents = keycloakContext.getRequestHeaders().getRequestHeader("User-Agent");

        if (userAgents != null) {
            attributes.put("kc.client.user_agent", userAgents);
        }

        attributes.put("kc.realm.name", Arrays.asList(keycloakContext.getRealm().getName()));

        if (claims != null) {
            for (Entry<String, List<String>> entry : claims.entrySet()) {
                attributes.put(entry.getKey(), entry.getValue());
            }
        }

        if (identity instanceof KeycloakIdentity) {
            AccessToken accessToken = ((KeycloakIdentity) this.identity).getAccessToken();

            if (accessToken != null) {
                attributes.put("kc.client.id", Arrays.asList(accessToken.getIssuedFor()));
            }
        }

        return attributes;
    }

    @Override
    public Attributes getAttributes() {
        if (attributes == null) {
            attributes = Attributes.from(getBaseAttributes());
        }
        return attributes;
    }
}
