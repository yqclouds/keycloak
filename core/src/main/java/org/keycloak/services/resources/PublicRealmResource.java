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
package org.keycloak.services.resources;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.representations.idm.PublishedRealmRepresentation;
import org.keycloak.services.resources.account.AccountFormService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.GET;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

/**
 * ResourceModel class for public realm information
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class PublicRealmResource {
    protected static final Logger LOG = LoggerFactory.getLogger(PublicRealmResource.class);

    @Context
    protected HttpRequest request;

    @Context
    protected HttpResponse response;

    protected RealmModel realm;
    @Autowired
    private KeycloakContext keycloakContext;

    public PublicRealmResource(RealmModel realm) {
        this.realm = realm;
    }

    @Autowired
    private KeyManager keyManager;

    public PublishedRealmRepresentation realmRep(RealmModel realm, UriInfo uriInfo) {
        PublishedRealmRepresentation rep = new PublishedRealmRepresentation();
        rep.setRealm(realm.getName());
        rep.setTokenServiceUrl(OIDCLoginProtocolService.tokenServiceBaseUrl(uriInfo).build(realm.getName()).toString());
        rep.setAccountServiceUrl(AccountFormService.accountServiceBaseUrl(uriInfo).build(realm.getName()).toString());
        rep.setPublicKeyPem(PemUtils.encodeKey(keyManager.getActiveRsaKey(realm).getPublicKey()));
        rep.setNotBefore(realm.getNotBefore());
        return rep;
    }

    /**
     * CORS preflight
     *
     * @return
     */
    @Path("/")
    @OPTIONS
    public Response accountPreflight() {
        return Cors.add(request, Response.ok()).auth().preflight().build();
    }

    /**
     * Public information about the realm.
     *
     * @return
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public PublishedRealmRepresentation getRealm() {
        Cors.add(request).allowedOrigins(Cors.ACCESS_CONTROL_ALLOW_ORIGIN_WILDCARD).auth().build(response);
        return realmRep(realm, keycloakContext.getUri());
    }


}
