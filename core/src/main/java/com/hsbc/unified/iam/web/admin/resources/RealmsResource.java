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

import com.hsbc.unified.iam.facade.spi.RealmFacade;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.policy.PasswordPolicyNotMetException;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.resources.admin.AdminRoot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.List;

/**
 * Top level resource for REST API
 */
@RestController
@RequestMapping(
        value = "/admin/realms",
        consumes = {MediaType.APPLICATION_JSON_VALUE},
        produces = {MediaType.APPLICATION_JSON_VALUE}
)
public class RealmsResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmsResource.class);

    @Autowired
    private RealmFacade realmFacade;

    @Autowired
    @Deprecated
    private KeycloakContext contextHolder;

    @ResponseStatus(value = HttpStatus.CONFLICT, reason = "Conflict detected. See logs for details")
    @ExceptionHandler(ModelDuplicateException.class)
    public void handleModelDuplicateException(ModelDuplicateException e) {
        LOG.error("Conflict detected", e);
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Password policy not met. See logs for details")
    @ExceptionHandler(PasswordPolicyNotMetException.class)
    public void handlePasswordPolicyNotMetException(PasswordPolicyNotMetException e) {
        LOG.error("Password policy not met for user " + e.getUsername(), e);
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN)
    @ExceptionHandler(ForbiddenException.class)
    public void handleForbiddenException() {
        // do nothing
    }

    /**
     * Import a realm
     * <p>
     * Imports a realm from a full representation of that realm.  Realm name must be unique.
     *
     * @param rep JSON representation of the realm
     */
    @RequestMapping(value = {"", "/"}, method = RequestMethod.POST)
    @PreAuthorize("hasPermission({'master', 'admin', 'create-realm'})")
    public Response createRealm(final RealmRepresentation rep) throws ModelDuplicateException, PasswordPolicyNotMetException {
        LOG.debug("createRealm: {}", rep.getRealm());

        RealmModel realm = realmFacade.createRealm(rep);

        URI location = AdminRoot.realmsUrl(contextHolder.getUri()).path(realm.getName()).build();
        LOG.debug("imported realm success, sending back: {}", location.toString());

        return Response.created(location).build();
    }

    /**
     * Get accessible realms
     * <p>
     * Returns a list of accessible realms. The list is filtered based on what realms the caller is allowed to view.
     */
    @RequestMapping(value = {"", "/"}, method = RequestMethod.GET)
    @PreAuthorize("hasPermission({'master', 'admin', 'view-realm', 'manage-realm'})")
    public List<RealmRepresentation> getRealms() throws ForbiddenException {
        LOG.debug(("getRealms()"));
        return realmFacade.getRealms();
    }
}
