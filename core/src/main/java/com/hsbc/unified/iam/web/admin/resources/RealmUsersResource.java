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

import com.hsbc.unified.iam.core.ClientConnection;
import com.hsbc.unified.iam.core.constants.Constants;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.policy.PasswordPolicyNotMetException;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * Base path for managing users in this realm.
 */
@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/users",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmUsersResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmUsersResource.class);

    @ResponseStatus(value = HttpStatus.CONFLICT, reason = "User exists with same username or email")
    @ExceptionHandler(ModelDuplicateException.class)
    public void handleModelDuplicateException(ModelDuplicateException e) {
        LOG.error("User exists with same username or email", e);
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Password policy not met")
    @ExceptionHandler(PasswordPolicyNotMetException.class)
    public void handlePasswordPolicyNotMetException(PasswordPolicyNotMetException e) {
        LOG.error("Password policy not met for user " + e.getUsername(), e);
    }

    @ResponseStatus(value = HttpStatus.BAD_REQUEST, reason = "Could not create user")
    @ExceptionHandler(ModelException.class)
    public void handleModelException(ModelException e) {
        LOG.error("Could not create user", e);
    }

    private static final String SEARCH_ID_PARAMETER = "id:";

    protected RealmModel realm;
    @Context
    protected ClientConnection clientConnection;
    @Context
    protected HttpHeaders headers;
    @Autowired
    private ModelToRepresentation modelToRepresentation;

    public RealmUsersResource(RealmModel realm) {
        this.realm = realm;
    }

    @Autowired
    private RealmUserResource userResource;
    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private UserProvider userProvider;
    @Autowired
    private KeycloakContext keycloakContext;

    /**
     * Create a new user
     * <p>
     * Username must be unique.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @PreAuthorize("hasPermission('manage-users')")
    public Response createUser(final UserRepresentation rep) throws ModelDuplicateException {
        String username = rep.getUsername();
        if (realm.isRegistrationEmailAsUsername()) {
            username = rep.getEmail();
        }

        if (ObjectUtil.isBlank(username)) {
            return ErrorResponse.error("User name is missing", Response.Status.BAD_REQUEST);
        }

        // Double-check duplicated username and email here due to federation
        if (userProvider.getUserByUsername(username, realm) != null) {
            return ErrorResponse.exists("User exists with same username");
        }

        if (rep.getEmail() != null && !realm.isDuplicateEmailsAllowed()
                && userProvider.getUserByEmail(rep.getEmail(), realm) != null) {
            return ErrorResponse.exists("User exists with same email");
        }

        UserModel user = userProvider.addUser(realm, username);
        Set<String> emptySet = Collections.emptySet();

        userResource.updateUserFromRep(user, rep, emptySet, realm, false);
        representationToModel.createFederatedIdentities(rep, realm, user);
        RepresentationToModel.createGroups(rep, realm, user);

        representationToModel.createCredentials(rep, realm, user, true);
        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(user.getId()).build()).build();
    }

    /**
     * Get representation of the user
     *
     * @param id User id
     */
    @Path("{id}")
    public RealmUserResource user(final @PathParam("id") String id) {
        UserModel user = userProvider.getUserById(id, realm);
        if (user == null) {
            throw new NotFoundException("User not found");
        }
        RealmUserResource resource = new RealmUserResource(realm, user);
        ResteasyProviderFactory.getInstance().injectProperties(resource);
        //resourceContext.initResource(users);
        return resource;
    }

    /**
     * Get users
     * <p>
     * Returns a list of users, filtered according to query parameters
     *
     * @param search A String contained in username, first or last name, or email
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<UserRepresentation> getUsers(@QueryParam("search") String search,
                                             @QueryParam("lastName") String last,
                                             @QueryParam("firstName") String first,
                                             @QueryParam("email") String email,
                                             @QueryParam("username") String username,
                                             @QueryParam("first") Integer firstResult,
                                             @QueryParam("max") Integer maxResults,
                                             @QueryParam("briefRepresentation") Boolean briefRepresentation) {
        firstResult = firstResult != null ? firstResult : -1;
        maxResults = maxResults != null ? maxResults : Constants.DEFAULT_MAX_RESULTS;

        List<UserModel> userModels = Collections.emptyList();
        if (search != null) {
            if (search.startsWith(SEARCH_ID_PARAMETER)) {
                UserModel userModel = userProvider.getUserById(search.substring(SEARCH_ID_PARAMETER.length()).trim(), realm);
                if (userModel != null) {
                    userModels = Collections.singletonList(userModel);
                }
            } else {
                Map<String, String> attributes = new HashMap<>();
                attributes.put(UserModel.SEARCH, search.trim());
                return searchForUser(attributes, realm, briefRepresentation, firstResult, maxResults, false);
            }
        } else if (last != null || first != null || email != null || username != null) {
            Map<String, String> attributes = new HashMap<>();
            if (last != null) {
                attributes.put(UserModel.LAST_NAME, last);
            }
            if (first != null) {
                attributes.put(UserModel.FIRST_NAME, first);
            }
            if (email != null) {
                attributes.put(UserModel.EMAIL, email);
            }
            if (username != null) {
                attributes.put(UserModel.USERNAME, username);
            }
            return searchForUser(attributes, realm, briefRepresentation, firstResult, maxResults, true);
        } else {
            return searchForUser(new HashMap<>(), realm, briefRepresentation, firstResult, maxResults, false);
        }

        return toRepresentation(realm, briefRepresentation, userModels);
    }

    /**
     * Returns the number of users that match the given criteria.
     * It can be called in three different ways.
     * 1. Don't specify any criteria and pass {@code null}. The number of all
     * users within that realm will be returned.
     * <p>
     * 2. If {@code search} is specified other criteria such as {@code last} will
     * be ignored even though you set them. The {@code search} string will be
     * matched against the first and last name, the username and the email of a
     * user.
     * <p>
     * 3. If {@code search} is unspecified but any of {@code last}, {@code first},
     * {@code email} or {@code username} those criteria are matched against their
     * respective fields on a user entity. Combined with a logical and.
     *
     * @param search   arbitrary search string for all the fields below
     * @param last     last name filter
     * @param first    first name filter
     * @param email    email filter
     * @param username username filter
     * @return the number of users that match the given criteria
     */
    @Path("count")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Integer getUsersCount(@QueryParam("search") String search,
                                 @QueryParam("lastName") String last,
                                 @QueryParam("firstName") String first,
                                 @QueryParam("email") String email,
                                 @QueryParam("username") String username) {
        if (search != null) {
            return userProvider.getUsersCount(search.trim(), realm);
        } else if (last != null || first != null || email != null || username != null) {
            Map<String, String> parameters = new HashMap<>();
            if (last != null) {
                parameters.put(UserModel.LAST_NAME, last);
            }
            if (first != null) {
                parameters.put(UserModel.FIRST_NAME, first);
            }
            if (email != null) {
                parameters.put(UserModel.EMAIL, email);
            }
            if (username != null) {
                parameters.put(UserModel.USERNAME, username);
            }
            return userProvider.getUsersCount(parameters, realm);
        } else {
            return userProvider.getUsersCount(realm);
        }
    }

    private HttpSession httpSession = null;

    private List<UserRepresentation> searchForUser(Map<String, String> attributes, RealmModel realm, Boolean briefRepresentation, Integer firstResult, Integer maxResults, Boolean includeServiceAccounts) {
        httpSession.setAttribute(UserModel.INCLUDE_SERVICE_ACCOUNT, includeServiceAccounts);

        List<UserModel> userModels = userProvider.searchForUser(attributes, realm, firstResult, maxResults);

        return toRepresentation(realm, briefRepresentation, userModels);
    }

    private List<UserRepresentation> toRepresentation(RealmModel realm, Boolean briefRepresentation, List<UserModel> userModels) {
        boolean briefRepresentationB = briefRepresentation != null && briefRepresentation;
        List<UserRepresentation> results = new ArrayList<>();

        for (UserModel user : userModels) {
            UserRepresentation userRep = briefRepresentationB
                    ? ModelToRepresentation.toBriefRepresentation(user)
                    : modelToRepresentation.toRepresentation(realm, user);
//            userRep.setAccess(usersEvaluator.getAccess(user));
            results.add(userRep);
        }
        return results;
    }
}
