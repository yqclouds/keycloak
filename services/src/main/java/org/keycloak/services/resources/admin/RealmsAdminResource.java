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
package org.keycloak.services.resources.admin;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import com.hsbc.unified.iam.common.ClientConnection;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.policy.PasswordPolicyNotMetException;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Top level resource for Admin REST API
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Realms Admin
 */
public class RealmsAdminResource {
    public static final CacheControl noCache = new CacheControl();
    protected static final Logger LOG = LoggerFactory.getLogger(RealmsAdminResource.class);

    static {
        noCache.setNoCache(true);
    }

    protected AdminAuth auth;
    protected TokenManager tokenManager;
    @Context
    protected KeycloakSession session;
    @Context
    protected KeycloakApplication keycloak;
    @Context
    protected ClientConnection clientConnection;

    public RealmsAdminResource(AdminAuth auth, TokenManager tokenManager) {
        this.auth = auth;
        this.tokenManager = tokenManager;
    }

    /**
     * Get accessible realms
     * <p>
     * Returns a list of accessible realms. The list is filtered based on what realms the caller is allowed to view.
     *
     * @return
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<RealmRepresentation> getRealms() {
        List<RealmRepresentation> reps = new ArrayList<>();
        List<RealmModel> realms = session.realms().getRealms();
        for (RealmModel realm : realms) {
            addRealmRep(reps, realm);
        }
        if (reps.isEmpty()) {
            throw new ForbiddenException();
        }

        LOG.debug(("getRealms()"));
        return reps;
    }

    protected void addRealmRep(List<RealmRepresentation> reps, RealmModel realm) {
        if (AdminPermissions.realms(session, auth).canView(realm)) {
            reps.add(ModelToRepresentation.toRepresentation(realm, false));
        } else if (AdminPermissions.realms(session, auth).isAdmin(realm)) {
            RealmRepresentation rep = new RealmRepresentation();
            rep.setRealm(realm.getName());
            reps.add(rep);
        }
    }

    /**
     * Import a realm
     * <p>
     * Imports a realm from a full representation of that realm.  Realm name must be unique.
     *
     * @param rep JSON representation of the realm
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response importRealm(final RealmRepresentation rep) {
        RealmManager realmManager = new RealmManager(session);
        AdminPermissions.realms(session, auth).requireCreateRealm();

        LOG.debug("importRealm: {}", rep.getRealm());

        try {
            RealmModel realm = realmManager.importRealm(rep);
            grantPermissionsToRealmCreator(realm);

            URI location = AdminRoot.realmsUrl(session.getContext().getUri()).path(realm.getName()).build();
            LOG.debug("imported realm success, sending back: {}", location.toString());

            return Response.created(location).build();
        } catch (ModelDuplicateException e) {
            LOG.error("Conflict detected", e);
            return ErrorResponse.exists("Conflict detected. See logs for details");
        } catch (PasswordPolicyNotMetException e) {
            LOG.error("Password policy not met for user " + e.getUsername(), e);
            if (session.getTransactionManager().isActive()) session.getTransactionManager().setRollbackOnly();
            return ErrorResponse.error("Password policy not met. See logs for details", Response.Status.BAD_REQUEST);
        }
    }

    private void grantPermissionsToRealmCreator(RealmModel realm) {
        if (auth.hasRealmRole(AdminRoles.ADMIN)) {
            return;
        }

        RealmModel adminRealm = new RealmManager(session).getKeycloakAdministrationRealm();
        ClientModel realmAdminApp = realm.getMasterAdminClient();
        for (String r : AdminRoles.ALL_REALM_ROLES) {
            RoleModel role = realmAdminApp.getRole(r);
            auth.getUser().grantRole(role);
        }
    }

    /**
     * Base path for the admin REST API for one particular realm.
     *
     * @param headers
     * @param name    realm name (not id!)
     * @return
     */
    @Path("{realm}")
    public RealmAdminResource getRealmAdmin(@Context final HttpHeaders headers,
                                            @PathParam("realm") final String name) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(name);
        if (realm == null) throw new NotFoundException("Realm not found.");

        if (!auth.getRealm().equals(realmManager.getKeycloakAdministrationRealm())
                && !auth.getRealm().equals(realm)) {
            throw new ForbiddenException();
        }
        AdminPermissionEvaluator realmAuth = AdminPermissions.evaluator(session, realm, auth);

        AdminEventBuilder adminEvent = new AdminEventBuilder(realm, auth, session, clientConnection);
        session.getContext().setRealm(realm);

        RealmAdminResource adminResource = new RealmAdminResource(realmAuth, realm, tokenManager, adminEvent);
        ResteasyProviderFactory.getInstance().injectProperties(adminResource);
        //resourceContext.initResource(adminResource);
        return adminResource;
    }

}
