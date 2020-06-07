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

package com.hsbc.unified.iam.web.admin.resources;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.LinkedList;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/keys",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmKeyResource {

    private RealmModel realm;
    @Autowired
    private KeyManager keyManager;

    public RealmKeyResource(RealmModel realm) {
        this.realm = realm;
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public KeysMetadataRepresentation getKeyMetadata() {
        KeysMetadataRepresentation keys = new KeysMetadataRepresentation();
        keys.setKeys(new LinkedList<>());
        keys.setActive(new HashMap<>());

        for (KeyWrapper key : keyManager.getKeys(realm)) {
            KeysMetadataRepresentation.KeyMetadataRepresentation r = new KeysMetadataRepresentation.KeyMetadataRepresentation();
            r.setProviderId(key.getProviderId());
            r.setProviderPriority(key.getProviderPriority());
            r.setKid(key.getKid());
            r.setStatus(key.getStatus() != null ? key.getStatus().name() : null);
            r.setType(key.getType());
            r.setAlgorithm(key.getAlgorithm());
            r.setPublicKey(key.getPublicKey() != null ? PemUtils.encodeKey(key.getPublicKey()) : null);
            r.setCertificate(key.getCertificate() != null ? PemUtils.encodeCertificate(key.getCertificate()) : null);
            keys.getKeys().add(r);

            if (key.getStatus().isActive()) {
                if (!keys.getActive().containsKey(key.getAlgorithm())) {
                    keys.getActive().put(key.getAlgorithm(), key.getKid());
                }
            }
        }

        return keys;
    }
}
