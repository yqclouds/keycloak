package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.util.Time;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.*;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import java.util.HashMap;
import java.util.Map;

/**
 * Base path for managing attack detection
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/attack-detection",
        consumes = {MediaType.APPLICATION_JSON_VALUE},
        produces = {MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmAttackDetectionResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmAttackDetectionResource.class);

    protected AdminPermissionEvaluator auth;
    protected RealmModel realm;
    @Context
    protected KeycloakContext keycloakContext;
    @Autowired
    private UserSessionProvider userSessionProvider;
    @Autowired
    private UserProvider userProvider;
    @Context
    protected ClientConnection connection;
    @Context
    protected HttpHeaders headers;

    public RealmAttackDetectionResource(AdminPermissionEvaluator auth, RealmModel realm) {
        this.auth = auth;
        this.realm = realm;
    }

    @Autowired
    private BruteForceProtector bruteForceProtector;


    /**
     * Get status of a username in brute force detection
     */
    @GET
    @Path("brute-force/users/{userId}")
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public Map<String, Object> bruteForceUserStatus(@PathParam("userId") String userId) {
        UserModel user = userProvider.getUserById(userId, realm);
        if (user == null) {
            auth.users().requireView();
        } else {
            auth.users().requireView(user);
        }

        Map<String, Object> data = new HashMap<>();
        data.put("disabled", false);
        data.put("numFailures", 0);
        data.put("lastFailure", 0);
        data.put("lastIPFailure", "n/a");
        if (!realm.isBruteForceProtected()) return data;


        UserLoginFailureModel model = userSessionProvider.getUserLoginFailure(realm, userId);
        if (model == null) return data;

        boolean disabled;
        if (user == null) {
            disabled = Time.currentTime() < model.getFailedLoginNotBefore();
        } else {
            disabled = bruteForceProtector.isTemporarilyDisabled(realm, user);
        }
        if (disabled) {
            data.put("disabled", true);
        }

        data.put("numFailures", model.getNumFailures());
        data.put("lastFailure", model.getLastFailure());
        data.put("lastIPFailure", model.getLastIPFailure());
        return data;
    }

    /**
     * Clear any user login failures for the user
     * <p>
     * This can release temporary disabled user
     */
    @Path("brute-force/users/{userId}")
    @DELETE
    public void clearBruteForceForUser(@PathParam("userId") String userId) {
        UserModel user = userProvider.getUserById(userId, realm);
        if (user == null) {
            auth.users().requireManage();
        } else {
            auth.users().requireManage(user);
        }
        UserLoginFailureModel model = userSessionProvider.getUserLoginFailure(realm, userId);
        if (model != null) {
            userSessionProvider.removeUserLoginFailure(realm, userId);
        }
    }

    /**
     * Clear any user login failures for all users
     * <p>
     * This can release temporary disabled users
     */
    @Path("brute-force/users")
    @DELETE
    public void clearAllBruteForce() {
        auth.users().requireManage();

        userSessionProvider.removeAllUserLoginFailures(realm);
    }
}
