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
package org.keycloak.authorization.admin;


import com.hsbc.unified.iam.facade.model.authorization.ResourceModel;
import com.hsbc.unified.iam.facade.model.authorization.ResourceServerModel;
import com.hsbc.unified.iam.facade.model.authorization.ScopeModel;
import org.keycloak.OAuthErrorException;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.admin.representation.PolicyEvaluationResponseBuilder;
import org.keycloak.authorization.attribute.Attributes;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.authorization.util.Permissions;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.*;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluationService {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyEvaluationService.class);

    private final AuthorizationProvider authorization;
    private final ResourceServerModel resourceServer;

    PolicyEvaluationService(ResourceServerModel resourceServer, AuthorizationProvider authorization) {
        this.resourceServer = resourceServer;
        this.authorization = authorization;
    }

    @Autowired
    private PolicyEvaluationResponseBuilder policyEvaluationResponseBuilder;

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response evaluate(PolicyEvaluationRequest evaluationRequest) {
        CloseableKeycloakIdentity identity = createIdentity(evaluationRequest);
        try {
            AuthorizationRequest request = new AuthorizationRequest();
            Map<String, List<String>> claims = new HashMap<>();
            Map<String, String> givenAttributes = evaluationRequest.getContext().get("attributes");

            if (givenAttributes != null) {
                givenAttributes.forEach((key, entryValue) -> {
                    if (entryValue != null) {
                        List<String> values = new ArrayList<>();
                        Collections.addAll(values, entryValue.split(","));

                        claims.put(key, values);
                    }
                });
            }

            request.setClaims(claims);

            return Response.ok(policyEvaluationResponseBuilder.build(evaluate(evaluationRequest, createEvaluationContext(evaluationRequest, identity), request), resourceServer, authorization, identity)).build();
        } catch (Exception e) {
            LOG.error("Error while evaluating permissions", e);
            throw new ErrorResponseException(OAuthErrorException.SERVER_ERROR, "Error while evaluating permissions.", Status.INTERNAL_SERVER_ERROR);
        } finally {
            identity.close();
        }
    }

    private EvaluationDecisionCollector evaluate(PolicyEvaluationRequest evaluationRequest, EvaluationContext evaluationContext, AuthorizationRequest request) {
        return authorization.evaluators().from(createPermissions(evaluationRequest, evaluationContext, authorization, request), evaluationContext).evaluate(new EvaluationDecisionCollector(authorization, resourceServer, request));
    }

    private EvaluationContext createEvaluationContext(PolicyEvaluationRequest representation, KeycloakIdentity identity) {
        return new DefaultEvaluationContext(identity) {
            @Override
            public Attributes getAttributes() {
                Map<String, Collection<String>> attributes = new HashMap<>(super.getAttributes().toMap());
                Map<String, String> givenAttributes = representation.getContext().get("attributes");

                if (givenAttributes != null) {
                    givenAttributes.forEach((key, entryValue) -> {
                        if (entryValue != null) {
                            List<String> values = new ArrayList<>();
                            Collections.addAll(values, entryValue.split(","));

                            attributes.put(key, values);
                        }
                    });
                }

                return Attributes.from(attributes);
            }
        };
    }

    private List<ResourcePermission> createPermissions(PolicyEvaluationRequest representation, EvaluationContext evaluationContext, AuthorizationProvider authorization, AuthorizationRequest request) {
        return representation.getResources().stream().flatMap((Function<ResourceRepresentation, Stream<ResourcePermission>>) resource -> {
            StoreFactory storeFactory = authorization.getStoreFactory();
            if (resource == null) {
                resource = new ResourceRepresentation();
            }

            Set<ScopeRepresentation> givenScopes = resource.getScopes();

            if (givenScopes == null) {
                givenScopes = new HashSet<>();
            }

            ScopeStore scopeStore = storeFactory.getScopeStore();

            Set<ScopeModel> scopes = givenScopes.stream().map(scopeRepresentation -> scopeStore.findByName(scopeRepresentation.getName(), resourceServer.getId())).collect(Collectors.toSet());

            if (resource.getId() != null) {
                ResourceModel resourceModel = storeFactory.getResourceStore().findById(resource.getId(), resourceServer.getId());
                return new ArrayList<>(Collections.singletonList(Permissions.createResourcePermissions(resourceModel, scopes, authorization, request))).stream();
            } else if (resource.getType() != null) {
                return storeFactory.getResourceStore().findByType(resource.getType(), resourceServer.getId()).stream().map(resource1 -> Permissions.createResourcePermissions(resource1, scopes, authorization, request));
            } else {
                if (scopes.isEmpty()) {
                    return Permissions.all(resourceServer, evaluationContext.getIdentity(), authorization, request).stream();
                }

                List<ResourceModel> resources = storeFactory.getResourceStore().findByScope(scopes.stream().map(ScopeModel::getId).collect(Collectors.toList()), resourceServer.getId());

                if (resources.isEmpty()) {
                    return scopes.stream().map(scope -> new ResourcePermission(null, new ArrayList<>(Collections.singletonList(scope)), resourceServer));
                }


                return resources.stream().map(resource12 -> Permissions.createResourcePermissions(resource12, scopes, authorization, request));
            }
        }).collect(Collectors.toList());
    }

    @Autowired
    private TokenManager tokenManager;
    @Autowired
    private KeycloakContext keycloakContext;
    @Autowired
    private UserProvider userProvider;
    @Autowired
    private AuthenticationSessionProvider authenticationSessionProvider;
    @Autowired
    private UserSessionProvider userSessionProvider;

    private CloseableKeycloakIdentity createIdentity(PolicyEvaluationRequest representation) {
        RealmModel realm = keycloakContext.getRealm();
        AccessToken accessToken = null;

        String subject = representation.getUserId();

        UserSessionModel userSession = null;
        if (subject != null) {
            UserModel userModel = userProvider.getUserById(subject, realm);

            if (userModel == null) {
                userModel = userProvider.getUserByUsername(subject, realm);
            }

            if (userModel != null) {
                String clientId = representation.getClientId();

                if (clientId == null) {
                    clientId = resourceServer.getId();
                }

                if (clientId != null) {
                    ClientModel clientModel = realm.getClientById(clientId);

                    AuthenticationSessionModel authSession = authenticationSessionProvider.createRootAuthenticationSession(realm)
                            .createAuthenticationSession(clientModel);
                    authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                    authSession.setAuthenticatedUser(userModel);
                    userSession = userSessionProvider.createUserSession(authSession.getParentSession().getId(), realm, userModel, userModel.getUsername(), "127.0.0.1", "passwd", false, null, null);

                    AuthenticationManager.setClientScopesInSession(authSession);
                    ClientSessionContext clientSessionCtx = tokenManager.attachAuthenticationSession(userSession, authSession);

                    accessToken = tokenManager.createClientAccessToken(realm, clientModel, userModel, userSession, clientSessionCtx);
                }
            }
        }

        if (accessToken == null) {
            accessToken = new AccessToken();

            accessToken.subject(representation.getUserId());
            ClientModel client = null;
            String clientId = representation.getClientId();

            if (clientId != null) {
                client = realm.getClientById(clientId);
            }

            if (client == null) {
                client = realm.getClientById(resourceServer.getId());
            }

            accessToken.issuedFor(client.getClientId());
            accessToken.audience(client.getId());
            accessToken.issuer(Urls.realmIssuer(keycloakContext.getUri().getBaseUri(), realm.getName()));
            accessToken.setRealmAccess(new AccessToken.Access());
        }

        if (representation.getRoleIds() != null && !representation.getRoleIds().isEmpty()) {
            if (accessToken.getRealmAccess() == null) {
                accessToken.setRealmAccess(new AccessToken.Access());
            }
            AccessToken.Access realmAccess = accessToken.getRealmAccess();

            representation.getRoleIds().forEach(realmAccess::addRole);
        }

        return new CloseableKeycloakIdentity(accessToken, userSession);
    }

    private class CloseableKeycloakIdentity extends KeycloakIdentity {
        private UserSessionModel userSession;

        public CloseableKeycloakIdentity(AccessToken accessToken, UserSessionModel userSession) {
            super(accessToken);
            this.userSession = userSession;
        }

        public void close() {
            if (userSession != null) {
                userSessionProvider.removeUserSession(realm, userSession);
            }
        }

        @Override
        public String getId() {
            if (userSession != null) {
                return super.getId();
            }

            String issuedFor = accessToken.getIssuedFor();

            if (issuedFor != null) {
                UserModel serviceAccount = userProvider.getServiceAccount(realm.getClientByClientId(issuedFor));

                if (serviceAccount != null) {
                    return serviceAccount.getId();
                }
            }

            return null;
        }
    }

    public static class EvaluationDecisionCollector extends DecisionPermissionCollector {
        public EvaluationDecisionCollector(AuthorizationProvider authorizationProvider, ResourceServerModel resourceServer, AuthorizationRequest request) {
            super(authorizationProvider, resourceServer, request);
        }

        @Override
        protected boolean isGranted(Result.PolicyResult policyResult) {
            if (super.isGranted(policyResult)) {
                policyResult.setEffect(Effect.PERMIT);
                return true;
            }
            return false;
        }

        @Override
        protected void grantPermission(AuthorizationProvider authorizationProvider, List<Permission> permissions, ResourcePermission permission, Collection<ScopeModel> grantedScopes, ResourceServerModel resourceServer, AuthorizationRequest request, Result result) {
            result.setStatus(Effect.PERMIT);
            result.getPermission().getScopes().retainAll(grantedScopes);
            super.grantPermission(authorizationProvider, permissions, permission, grantedScopes, resourceServer, request, result);
        }

        public Collection<Result> getResults() {
            return results.values();
        }
    }
}