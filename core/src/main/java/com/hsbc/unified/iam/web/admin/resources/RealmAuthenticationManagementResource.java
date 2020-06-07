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

import com.hsbc.unified.iam.entity.AuthenticationExecutionRequirement;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.*;
import org.keycloak.services.ErrorResponse;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.ReservedCharValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.*;

import static javax.ws.rs.core.Response.Status.NOT_FOUND;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/authentication",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmAuthenticationManagementResource {
    protected static final Logger LOG = LoggerFactory.getLogger(RealmAuthenticationManagementResource.class);

    private final RealmModel realm;

    public RealmAuthenticationManagementResource(RealmModel realm) {
        this.realm = realm;
    }

    public static AuthenticationFlowModel copyFlow(RealmModel realm, AuthenticationFlowModel flow, String newName) {
        AuthenticationFlowModel copy = new AuthenticationFlowModel();
        copy.setAlias(newName);
        copy.setDescription(flow.getDescription());
        copy.setProviderId(flow.getProviderId());
        copy.setBuiltIn(false);
        copy.setTopLevel(flow.isTopLevel());
        copy = realm.addAuthenticationFlow(copy);
        copy(realm, newName, flow, copy);
        return copy;
    }

    public static void copy(RealmModel realm, String newName, AuthenticationFlowModel from, AuthenticationFlowModel to) {
        for (AuthenticationExecutionModel execution : realm.getAuthenticationExecutions(from.getId())) {
            if (execution.isAuthenticatorFlow()) {
                AuthenticationFlowModel subFlow = realm.getAuthenticationFlowById(execution.getFlowId());
                AuthenticationFlowModel copy = new AuthenticationFlowModel();
                copy.setAlias(newName + " " + subFlow.getAlias());
                copy.setDescription(subFlow.getDescription());
                copy.setProviderId(subFlow.getProviderId());
                copy.setBuiltIn(false);
                copy.setTopLevel(false);
                copy = realm.addAuthenticationFlow(copy);
                execution.setFlowId(copy.getId());
                copy(realm, newName, subFlow, copy);
            }
            execution.setId(null);
            execution.setParentFlow(to.getId());
            realm.addAuthenticatorExecution(execution);
        }
    }

    public static RequiredActionProviderRepresentation toRepresentation(RequiredActionProviderModel model) {
        RequiredActionProviderRepresentation rep = new RequiredActionProviderRepresentation();
        rep.setAlias(model.getAlias());
        rep.setProviderId(model.getProviderId());
        rep.setName(model.getName());
        rep.setDefaultAction(model.isDefaultAction());
        rep.setPriority(model.getPriority());
        rep.setEnabled(model.isEnabled());
        rep.setConfig(model.getConfig());
        return rep;
    }

    /**
     * Get form providers
     * <p>
     * Returns a list of form providers.
     */
    @Path("/form-providers")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> getFormProviders() {
        return buildProviderMetadata(formAuthenticatorFactories);
    }

    @Autowired
    private List<FormAuthenticatorFactory> formAuthenticatorFactories;

    /**
     * Get authenticator providers
     * <p>
     * Returns a list of authenticator providers.
     */
    @Path("/authenticator-providers")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> getAuthenticatorProviders() {
        return buildProviderMetadata(authenticatorFactories);
    }

    @Autowired
    private List<AuthenticatorFactory> authenticatorFactories;

    /**
     * Get client authenticator providers
     * <p>
     * Returns a list of client authenticator providers.
     */
    @Path("/client-authenticator-providers")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> getClientAuthenticatorProviders() {
        return buildProviderMetadata(clientAuthenticatorFactories);
    }

    @Autowired
    private List<ClientAuthenticatorFactory> clientAuthenticatorFactories;

    public List<Map<String, Object>> buildProviderMetadata(List<? extends ProviderFactory> factories) {
        List<Map<String, Object>> providers = new LinkedList<>();
        for (ProviderFactory factory : factories) {
            Map<String, Object> data = new HashMap<>();
            data.put("id", factory.getId());
            ConfigurableAuthenticatorFactory configured = (ConfigurableAuthenticatorFactory) factory;
            data.put("description", configured.getHelpText());
            data.put("displayName", configured.getDisplayType());

            providers.add(data);
        }
        return providers;
    }

    /**
     * Get form action providers
     * <p>
     * Returns a list of form action providers.
     */
    @Path("/form-action-providers")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<Map<String, Object>> getFormActionProviders() {
        return buildProviderMetadata(formActionFactories);
    }

    @Autowired
    private List<FormActionFactory> formActionFactories;

    /**
     * Get authentication flows
     * <p>
     * Returns a list of authentication flows.
     */
    @Path("/flows")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public List<AuthenticationFlowRepresentation> getFlows() {
        List<AuthenticationFlowRepresentation> flows = new LinkedList<>();
        for (AuthenticationFlowModel flow : realm.getAuthenticationFlows()) {
            // KEYCLOAK-3517, we need a better way to filter non-configurable internal flows
            if (flow.isTopLevel()) {
                flows.add(ModelToRepresentation.toRepresentation(realm, flow));
            }
        }
        return flows;
    }

    @Autowired
    private KeycloakContext keycloakContext;

    /**
     * Create a new authentication flow
     *
     * @param flow Authentication flow representation
     */
    @Path("/flows")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createFlow(AuthenticationFlowRepresentation flow) {
        if (flow.getAlias() == null || flow.getAlias().isEmpty()) {
            return ErrorResponse.exists("Failed to create flow with empty alias name");
        }

        if (realm.getFlowByAlias(flow.getAlias()) != null) {
            return ErrorResponse.exists("Flow " + flow.getAlias() + " already exists");
        }

        ReservedCharValidator.validate(flow.getAlias());

        AuthenticationFlowModel createdModel = realm.addAuthenticationFlow(RepresentationToModel.toModel(flow));

        flow.setId(createdModel.getId());
        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(flow.getId()).build()).build();
    }

    /**
     * Get authentication flow for id
     *
     * @param id Flow id
     */
    @Path("/flows/{id}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public AuthenticationFlowRepresentation getFlow(@PathParam("id") String id) {
        AuthenticationFlowModel flow = realm.getAuthenticationFlowById(id);
        if (flow == null) {
            throw new NotFoundException("Could not find flow with id");
        }
        return ModelToRepresentation.toRepresentation(realm, flow);
    }

    /**
     * Update an authentication flow
     *
     * @param flow Authentication flow representation
     */
    @Path("/flows/{id}")
    @PUT
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response updateFlow(@PathParam("id") String id, AuthenticationFlowRepresentation flow) {
        AuthenticationFlowRepresentation existingFlow = getFlow(id);

        if (flow.getAlias() == null || flow.getAlias().isEmpty()) {
            return ErrorResponse.exists("Failed to update flow with empty alias name");
        }

        flow.setId(existingFlow.getId());
        realm.updateAuthenticationFlow(RepresentationToModel.toModel(flow));

        return Response.accepted(flow).build();
    }

    /**
     * Delete an authentication flow
     *
     * @param id Flow id
     */
    @Path("/flows/{id}")
    @DELETE
    @NoCache
    public void deleteFlow(@PathParam("id") String id) {
        deleteFlow(id, true);
    }

    private void deleteFlow(String id, boolean isTopMostLevel) {
        AuthenticationFlowModel flow = realm.getAuthenticationFlowById(id);
        if (flow == null) {
            throw new NotFoundException("Could not find flow with id");
        }
        if (flow.isBuiltIn()) {
            throw new BadRequestException("Can't delete built in flow");
        }

        List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutions(id);
        for (AuthenticationExecutionModel execution : executions) {
            if (execution.getFlowId() != null) {
                deleteFlow(execution.getFlowId(), false);
            }
        }
        realm.removeAuthenticationFlow(flow);
    }

    /**
     * Copy existing authentication flow under a new name
     * <p>
     * The new name is given as 'newName' attribute of the passed JSON object
     *
     * @param flowAlias Name of the existing authentication flow
     * @param data      JSON containing 'newName' attribute
     */
    @Path("/flows/{flowAlias}/copy")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response copy(@PathParam("flowAlias") String flowAlias, Map<String, String> data) {
        String newName = data.get("newName");
        if (realm.getFlowByAlias(newName) != null) {
            return ErrorResponse.exists("New flow alias name already exists");
        }

        AuthenticationFlowModel flow = realm.getFlowByAlias(flowAlias);
        if (flow == null) {
            LOG.debug("flow not found: " + flowAlias);
            return Response.status(NOT_FOUND).build();
        }
        AuthenticationFlowModel copy = copyFlow(realm, flow, newName);

        data.put("id", copy.getId());

        return Response.status(Response.Status.CREATED).build();

    }

    /**
     * Add new flow with new execution to existing flow
     *
     * @param flowAlias Alias of parent authentication flow
     * @param data      New authentication flow / execution JSON data containing 'alias', 'type', 'provider', and 'description' attributes
     */
    @Path("/flows/{flowAlias}/executions/flow")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addExecutionFlow(@PathParam("flowAlias") String flowAlias, Map<String, String> data) {
        AuthenticationFlowModel parentFlow = realm.getFlowByAlias(flowAlias);
        if (parentFlow == null) {
            return ErrorResponse.error("Parent flow doesn't exists", Response.Status.BAD_REQUEST);
        }
        String alias = data.get("alias");
        String type = data.get("type");
        String provider = data.get("provider");
        String description = data.get("description");


        AuthenticationFlowModel newFlow = realm.getFlowByAlias(alias);
        if (newFlow != null) {
            return ErrorResponse.exists("New flow alias name already exists");
        }
        newFlow = new AuthenticationFlowModel();
        newFlow.setAlias(alias);
        newFlow.setDescription(description);
        newFlow.setProviderId(type);
        newFlow = realm.addAuthenticationFlow(newFlow);
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setParentFlow(parentFlow.getId());
        execution.setFlowId(newFlow.getId());
        execution.setRequirement(AuthenticationExecutionRequirement.DISABLED);
        execution.setAuthenticatorFlow(true);
        execution.setAuthenticator(provider);
        execution.setPriority(getNextPriority(parentFlow));
        execution = realm.addAuthenticatorExecution(execution);

        data.put("id", execution.getId());

        String addExecutionPathSegment = UriBuilder.fromMethod(RealmAuthenticationManagementResource.class, "addExecutionFlow").build(parentFlow.getAlias()).getPath();
        return Response.created(keycloakContext.getUri().getBaseUriBuilder().path(keycloakContext.getUri().getPath().replace(addExecutionPathSegment, "")).path("flows").path(newFlow.getId()).build()).build();
    }

    private int getNextPriority(AuthenticationFlowModel parentFlow) {
        List<AuthenticationExecutionModel> executions = getSortedExecutions(parentFlow);
        return executions.isEmpty() ? 0 : executions.get(executions.size() - 1).getPriority() + 1;
    }

    @Autowired
    private KeycloakSessionFactory sessionFactory;

    /**
     * Add new authentication execution to a flow
     *
     * @param flowAlias Alias of parent flow
     * @param data      New execution JSON data containing 'provider' attribute
     */
    @Path("/flows/{flowAlias}/executions/execution")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addExecutionToFlow(@PathParam("flowAlias") String flowAlias, Map<String, String> data) {
        AuthenticationFlowModel parentFlow = realm.getFlowByAlias(flowAlias);
        if (parentFlow == null) {
            throw new BadRequestException("Parent flow doesn't exists");
        }
        if (parentFlow.isBuiltIn()) {
            throw new BadRequestException("It is illegal to add execution to a built in flow");
        }
        String provider = data.get("provider");

        // make sure provider is one of the registered providers
        ProviderFactory f;
        if (parentFlow.getProviderId().equals(AuthenticationFlow.CLIENT_FLOW)) {
            f = sessionFactory.getProviderFactory(ClientAuthenticator.class, provider);
        } else if (parentFlow.getProviderId().equals(AuthenticationFlow.FORM_FLOW)) {
            f = sessionFactory.getProviderFactory(FormAction.class, provider);
        } else {
            f = sessionFactory.getProviderFactory(Authenticator.class, provider);
        }
        if (f == null) {
            throw new BadRequestException("No authentication provider found for id: " + provider);
        }

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setParentFlow(parentFlow.getId());

        ConfigurableAuthenticatorFactory conf = (ConfigurableAuthenticatorFactory) f;
        if (conf.getRequirementChoices().length == 1)
            execution.setRequirement(conf.getRequirementChoices()[0]);
        else
            execution.setRequirement(AuthenticationExecutionRequirement.DISABLED);

        execution.setAuthenticatorFlow(false);
        execution.setAuthenticator(provider);
        execution.setPriority(getNextPriority(parentFlow));

        execution = realm.addAuthenticatorExecution(execution);

        data.put("id", execution.getId());

        String addExecutionPathSegment = UriBuilder.fromMethod(RealmAuthenticationManagementResource.class, "addExecutionToFlow").build(parentFlow.getAlias()).getPath();
        return Response.created(keycloakContext.getUri().getBaseUriBuilder().path(keycloakContext.getUri().getPath().replace(addExecutionPathSegment, "")).path("executions").path(execution.getId()).build()).build();
    }

    /**
     * Get authentication executions for a flow
     *
     * @param flowAlias Flow alias
     */
    @Path("/flows/{flowAlias}/executions")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response getExecutions(@PathParam("flowAlias") String flowAlias) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(flowAlias);
        if (flow == null) {
            LOG.debug("flow not found: " + flowAlias);
            return Response.status(NOT_FOUND).build();
        }
        List<AuthenticationExecutionInfoRepresentation> result = new LinkedList<>();

        int level = 0;

        recurseExecutions(flow, result, level);
        return Response.ok(result).build();
    }

    public void recurseExecutions(AuthenticationFlowModel flow, List<AuthenticationExecutionInfoRepresentation> result, int level) {
        int index = 0;
        List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutions(flow.getId());
        for (AuthenticationExecutionModel execution : executions) {
            AuthenticationExecutionInfoRepresentation rep = new AuthenticationExecutionInfoRepresentation();
            rep.setLevel(level);
            rep.setIndex(index++);
            rep.setRequirementChoices(new LinkedList<String>());
            if (execution.isAuthenticatorFlow()) {
                AuthenticationFlowModel flowRef = realm.getAuthenticationFlowById(execution.getFlowId());
                if (AuthenticationFlow.BASIC_FLOW.equals(flowRef.getProviderId())) {
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.REQUIRED.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.ALTERNATIVE.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.DISABLED.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.CONDITIONAL.name());
                } else if (AuthenticationFlow.FORM_FLOW.equals(flowRef.getProviderId())) {
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.REQUIRED.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.DISABLED.name());
                    rep.setProviderId(execution.getAuthenticator());
                    rep.setAuthenticationConfig(execution.getAuthenticatorConfig());
                } else if (AuthenticationFlow.CLIENT_FLOW.equals(flowRef.getProviderId())) {
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.ALTERNATIVE.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.REQUIRED.name());
                    rep.getRequirementChoices().add(AuthenticationExecutionRequirement.DISABLED.name());
                }
                rep.setDisplayName(flowRef.getAlias());
                rep.setConfigurable(false);
                rep.setId(execution.getId());
                rep.setAuthenticationFlow(execution.isAuthenticatorFlow());
                rep.setRequirement(execution.getRequirement().name());
                rep.setFlowId(execution.getFlowId());
                result.add(rep);
                AuthenticationFlowModel subFlow = realm.getAuthenticationFlowById(execution.getFlowId());
                recurseExecutions(subFlow, result, level + 1);
            } else {
                String providerId = execution.getAuthenticator();
                ConfigurableAuthenticatorFactory factory = credentialHelper.getConfigurableAuthenticatorFactory(providerId);
                rep.setDisplayName(factory.getDisplayType());
                rep.setConfigurable(factory.isConfigurable());
                for (AuthenticationExecutionRequirement choice : factory.getRequirementChoices()) {
                    rep.getRequirementChoices().add(choice.name());
                }
                rep.setId(execution.getId());

                if (factory.isConfigurable()) {
                    String authenticatorConfigId = execution.getAuthenticatorConfig();
                    if (authenticatorConfigId != null) {
                        AuthenticatorConfigModel authenticatorConfig = realm.getAuthenticatorConfigById(authenticatorConfigId);

                        if (authenticatorConfig != null) {
                            rep.setAlias(authenticatorConfig.getAlias());
                        }
                    }
                }

                rep.setRequirement(execution.getRequirement().name());
                rep.setProviderId(execution.getAuthenticator());
                rep.setAuthenticationConfig(execution.getAuthenticatorConfig());
                result.add(rep);
            }
        }
    }

    /**
     * Update authentication executions of a flow
     *
     * @param flowAlias Flow alias
     */
    @Path("/flows/{flowAlias}/executions")
    @PUT
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateExecutions(@PathParam("flowAlias") String flowAlias, AuthenticationExecutionInfoRepresentation rep) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(flowAlias);
        if (flow == null) {
            LOG.debug("flow not found: " + flowAlias);
            throw new NotFoundException("flow not found");
        }

        AuthenticationExecutionModel model = realm.getAuthenticationExecutionById(rep.getId());
        if (model == null) {
            throw new NotFoundException("Illegal execution");

        }
        if (!model.getRequirement().name().equals(rep.getRequirement())) {
            model.setRequirement(AuthenticationExecutionRequirement.valueOf(rep.getRequirement()));
            realm.updateAuthenticatorExecution(model);
        }
    }

    /**
     * Get Single Execution
     */
    @Path("/executions/{executionId}")
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public Response getExecution(final @PathParam("executionId") String executionId) {
        final Optional<AuthenticationExecutionModel> model = Optional.ofNullable(realm.getAuthenticationExecutionById(executionId));
        if (!model.isPresent()) {
            LOG.debug("Could not find execution by Id: {}", executionId);
            throw new NotFoundException("Illegal execution");
        }

        return Response.ok(model.get()).build();
    }

    /**
     * Add new authentication execution
     *
     * @param execution JSON model describing authentication execution
     */
    @Path("/executions")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response addExecution(AuthenticationExecutionRepresentation execution) {
        AuthenticationExecutionModel model = RepresentationToModel.toModel(realm, execution);
        AuthenticationFlowModel parentFlow = getParentFlow(model);
        if (parentFlow.isBuiltIn()) {
            throw new BadRequestException("It is illegal to add execution to a built in flow");
        }
        model.setPriority(getNextPriority(parentFlow));
        model = realm.addAuthenticatorExecution(model);

        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(model.getId()).build()).build();
    }

    public AuthenticationFlowModel getParentFlow(AuthenticationExecutionModel model) {
        if (model.getParentFlow() == null) {
            throw new BadRequestException("parent flow not set on new execution");
        }
        AuthenticationFlowModel parentFlow = realm.getAuthenticationFlowById(model.getParentFlow());
        if (parentFlow == null) {
            throw new BadRequestException("execution parent flow does not exist");

        }
        return parentFlow;
    }

    /**
     * Raise execution's priority
     *
     * @param execution Execution id
     */
    @Path("/executions/{executionId}/raise-priority")
    @POST
    @NoCache
    public void raisePriority(@PathParam("executionId") String execution) {
        AuthenticationExecutionModel model = realm.getAuthenticationExecutionById(execution);
        if (model == null) {
            throw new NotFoundException("Illegal execution");

        }
        AuthenticationFlowModel parentFlow = getParentFlow(model);
        if (parentFlow.isBuiltIn()) {
            throw new BadRequestException("It is illegal to modify execution in a built in flow");
        }
        List<AuthenticationExecutionModel> executions = getSortedExecutions(parentFlow);
        AuthenticationExecutionModel previous = null;
        for (AuthenticationExecutionModel exe : executions) {
            if (exe.getId().equals(model.getId())) {
                break;
            }
            previous = exe;

        }
        if (previous == null) return;
        int tmp = previous.getPriority();
        previous.setPriority(model.getPriority());
        realm.updateAuthenticatorExecution(previous);
        model.setPriority(tmp);
        realm.updateAuthenticatorExecution(model);
    }

    public List<AuthenticationExecutionModel> getSortedExecutions(AuthenticationFlowModel parentFlow) {
        List<AuthenticationExecutionModel> executions = new LinkedList<>(realm.getAuthenticationExecutions(parentFlow.getId()));
        executions.sort(AuthenticationExecutionModel.ExecutionComparator.SINGLETON);
        return executions;
    }

    /**
     * Lower execution's priority
     *
     * @param execution Execution id
     */
    @Path("/executions/{executionId}/lower-priority")
    @POST
    @NoCache
    public void lowerPriority(@PathParam("executionId") String execution) {
        AuthenticationExecutionModel model = realm.getAuthenticationExecutionById(execution);
        if (model == null) {
            throw new NotFoundException("Illegal execution");

        }
        AuthenticationFlowModel parentFlow = getParentFlow(model);
        if (parentFlow.isBuiltIn()) {
            throw new BadRequestException("It is illegal to modify execution in a built in flow");
        }
        List<AuthenticationExecutionModel> executions = getSortedExecutions(parentFlow);
        int i = 0;
        for (i = 0; i < executions.size(); i++) {
            if (executions.get(i).getId().equals(model.getId())) {
                break;
            }
        }
        if (i + 1 >= executions.size()) return;
        AuthenticationExecutionModel next = executions.get(i + 1);
        int tmp = model.getPriority();
        model.setPriority(next.getPriority());
        realm.updateAuthenticatorExecution(model);
        next.setPriority(tmp);
        realm.updateAuthenticatorExecution(next);
    }

    /**
     * Delete execution
     *
     * @param execution Execution id
     */
    @Path("/executions/{executionId}")
    @DELETE
    @NoCache
    public void removeExecution(@PathParam("executionId") String execution) {
        AuthenticationExecutionModel model = realm.getAuthenticationExecutionById(execution);
        if (model == null) {
            throw new NotFoundException("Illegal execution");

        }
        AuthenticationFlowModel parentFlow = getParentFlow(model);
        if (parentFlow.isBuiltIn()) {
            throw new BadRequestException("It is illegal to remove execution from a built in flow");
        }

        if (model.getFlowId() != null) {
            AuthenticationFlowModel nonTopLevelFlow = realm.getAuthenticationFlowById(model.getFlowId());
            realm.removeAuthenticationFlow(nonTopLevelFlow);
        }

        realm.removeAuthenticatorExecution(model);
    }

    /**
     * Update execution with new configuration
     *
     * @param execution Execution id
     * @param json      JSON with new configuration
     */
    @Path("/executions/{executionId}/config")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response newExecutionConfig(@PathParam("executionId") String execution, AuthenticatorConfigRepresentation json) {
        ReservedCharValidator.validate(json.getAlias());

        AuthenticationExecutionModel model = realm.getAuthenticationExecutionById(execution);
        if (model == null) {
            throw new NotFoundException("Illegal execution");

        }
        AuthenticatorConfigModel config = RepresentationToModel.toModel(json);
        if (config.getAlias() == null) {
            return ErrorResponse.error("Alias missing", Response.Status.BAD_REQUEST);
        }
        config = realm.addAuthenticatorConfig(config);
        model.setAuthenticatorConfig(config.getId());
        realm.updateAuthenticatorExecution(model);

        json.setId(config.getId());
        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(config.getId()).build()).build();
    }

    /**
     * Get execution's configuration
     *
     * @param execution Execution id
     * @param id        Configuration id
     * @deprecated Use rather {@link #getAuthenticatorConfig(String)}
     */
    @Path("/executions/{executionId}/config/{id}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public AuthenticatorConfigRepresentation getAuthenticatorConfig(@PathParam("executionId") String execution, @PathParam("id") String id) {
        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(id);
        if (config == null) {
            throw new NotFoundException("Could not find authenticator config");

        }
        return ModelToRepresentation.toRepresentation(config);
    }

    /**
     * Get unregistered required actions
     * <p>
     * Returns a list of unregistered required actions.
     */
    @Path("unregistered-required-actions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<Map<String, String>> getUnregisteredRequiredActions() {
        List<ProviderFactory> factories = sessionFactory.getProviderFactories(RequiredActionProvider.class);
        List<Map<String, String>> unregisteredList = new LinkedList<>();
        for (ProviderFactory factory : factories) {
            RequiredActionFactory requiredActionFactory = (RequiredActionFactory) factory;
            boolean found = false;
            for (RequiredActionProviderModel model : realm.getRequiredActionProviders()) {
                if (model.getProviderId().equals(factory.getId())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                Map<String, String> data = new HashMap<>();
                data.put("name", requiredActionFactory.getDisplayText());
                data.put("providerId", requiredActionFactory.getId());
                unregisteredList.add(data);
            }

        }
        return unregisteredList;
    }

    /**
     * Register a new required actions
     *
     * @param data JSON containing 'providerId', and 'name' attributes.
     */
    @Path("register-required-action")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public void registerRequiredAction(Map<String, String> data) {
        String providerId = data.get("providerId");
        String name = data.get("name");
        RequiredActionProviderModel requiredAction = new RequiredActionProviderModel();
        requiredAction.setAlias(providerId);
        requiredAction.setName(name);
        requiredAction.setProviderId(providerId);
        requiredAction.setDefaultAction(false);
        requiredAction.setPriority(getNextRequiredActionPriority());
        requiredAction.setEnabled(true);
        requiredAction = realm.addRequiredActionProvider(requiredAction);

        data.put("id", requiredAction.getId());
    }

    private int getNextRequiredActionPriority() {
        List<RequiredActionProviderModel> actions = realm.getRequiredActionProviders();
        return actions.isEmpty() ? 0 : actions.get(actions.size() - 1).getPriority() + 1;
    }

    /**
     * Get required actions
     * <p>
     * Returns a list of required actions.
     */
    @Path("required-actions")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RequiredActionProviderRepresentation> getRequiredActions() {
        List<RequiredActionProviderRepresentation> list = new LinkedList<>();
        for (RequiredActionProviderModel model : realm.getRequiredActionProviders()) {
            RequiredActionProviderRepresentation rep = toRepresentation(model);
            list.add(rep);
        }
        return list;
    }

    /**
     * Get required action for alias
     *
     * @param alias Alias of required action
     */
    @Path("required-actions/{alias}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public RequiredActionProviderRepresentation getRequiredAction(@PathParam("alias") String alias) {
        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            throw new NotFoundException("Failed to find required action");
        }
        return toRepresentation(model);
    }


    /**
     * Update required action
     *
     * @param alias Alias of required action
     * @param rep   JSON describing new state of required action
     */
    @Path("required-actions/{alias}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void updateRequiredAction(@PathParam("alias") String alias, RequiredActionProviderRepresentation rep) {
        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            throw new NotFoundException("Failed to find required action");
        }
        RequiredActionProviderModel update = new RequiredActionProviderModel();
        update.setId(model.getId());
        update.setName(rep.getName());
        update.setAlias(rep.getAlias());
        update.setProviderId(model.getProviderId());
        update.setDefaultAction(rep.isDefaultAction());
        update.setPriority(rep.getPriority());
        update.setEnabled(rep.isEnabled());
        update.setConfig(rep.getConfig());
        realm.updateRequiredActionProvider(update);
    }

    /**
     * Delete required action
     *
     * @param alias Alias of required action
     */
    @Path("required-actions/{alias}")
    @DELETE
    public void removeRequiredAction(@PathParam("alias") String alias) {
        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            throw new NotFoundException("Failed to find required action.");
        }
        realm.removeRequiredActionProvider(model);
    }

    /**
     * Raise required action's priority
     *
     * @param alias Alias of required action
     */
    @Path("required-actions/{alias}/raise-priority")
    @POST
    @NoCache
    public void raiseRequiredActionPriority(@PathParam("alias") String alias) {
        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            throw new NotFoundException("Failed to find required action.");
        }

        List<RequiredActionProviderModel> actions = realm.getRequiredActionProviders();
        RequiredActionProviderModel previous = null;
        for (RequiredActionProviderModel action : actions) {
            if (action.getId().equals(model.getId())) {
                break;
            }
            previous = action;
        }
        if (previous == null) return;
        int tmp = previous.getPriority();
        previous.setPriority(model.getPriority());
        realm.updateRequiredActionProvider(previous);
        model.setPriority(tmp);
        realm.updateRequiredActionProvider(model);
    }

    /**
     * Lower required action's priority
     *
     * @param alias Alias of required action
     */
    @Path("/required-actions/{alias}/lower-priority")
    @POST
    @NoCache
    public void lowerRequiredActionPriority(@PathParam("alias") String alias) {
        RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(alias);
        if (model == null) {
            throw new NotFoundException("Failed to find required action.");
        }

        List<RequiredActionProviderModel> actions = realm.getRequiredActionProviders();
        int i = 0;
        for (i = 0; i < actions.size(); i++) {
            if (actions.get(i).getId().equals(model.getId())) {
                break;
            }
        }
        if (i + 1 >= actions.size()) return;
        RequiredActionProviderModel next = actions.get(i + 1);
        int tmp = model.getPriority();
        model.setPriority(next.getPriority());
        realm.updateRequiredActionProvider(model);
        next.setPriority(tmp);
        realm.updateRequiredActionProvider(next);
    }

    @Autowired
    private CredentialHelper credentialHelper;

    /**
     * Get authenticator provider's configuration description
     */
    @Path("config-description/{providerId}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public AuthenticatorConfigInfoRepresentation getAuthenticatorConfigDescription(@PathParam("providerId") String providerId) {
        ConfigurableAuthenticatorFactory factory = credentialHelper.getConfigurableAuthenticatorFactory(providerId);
        if (factory == null) {
            throw new NotFoundException("Could not find authenticator provider");
        }
        AuthenticatorConfigInfoRepresentation rep = new AuthenticatorConfigInfoRepresentation();
        rep.setProviderId(providerId);
        rep.setName(factory.getDisplayType());
        rep.setHelpText(factory.getHelpText());
        rep.setProperties(new LinkedList<>());
        List<ProviderConfigProperty> configProperties = factory.getConfigProperties();
        for (ProviderConfigProperty prop : configProperties) {
            ConfigPropertyRepresentation propRep = getConfigPropertyRep(prop);
            rep.getProperties().add(propRep);
        }
        return rep;
    }

    private ConfigPropertyRepresentation getConfigPropertyRep(ProviderConfigProperty prop) {
        return ModelToRepresentation.toRepresentation(prop);
    }

    /**
     * Get configuration descriptions for all clients
     */
    @Path("per-client-config-description")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Map<String, List<ConfigPropertyRepresentation>> getPerClientConfigDescription() {
        List<ProviderFactory> factories = sessionFactory.getProviderFactories(ClientAuthenticator.class);

        Map<String, List<ConfigPropertyRepresentation>> toReturn = new HashMap<>();
        for (ProviderFactory clientAuthenticatorFactory : factories) {
            String providerId = clientAuthenticatorFactory.getId();
            ConfigurableAuthenticatorFactory factory = credentialHelper.getConfigurableAuthenticatorFactory(providerId);
            ClientAuthenticatorFactory clientAuthFactory = (ClientAuthenticatorFactory) factory;
            List<ProviderConfigProperty> perClientConfigProps = clientAuthFactory.getConfigPropertiesPerClient();
            List<ConfigPropertyRepresentation> result = new LinkedList<>();
            for (ProviderConfigProperty prop : perClientConfigProps) {
                ConfigPropertyRepresentation propRep = getConfigPropertyRep(prop);
                result.add(propRep);
            }

            toReturn.put(providerId, result);
        }

        return toReturn;
    }

    /**
     * Create new authenticator configuration
     *
     * @param rep JSON describing new authenticator configuration
     * @deprecated Use {@link #newExecutionConfig(String, AuthenticatorConfigRepresentation)} instead
     */
    @Path("config")
    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createAuthenticatorConfig(AuthenticatorConfigRepresentation rep) {
        ReservedCharValidator.validate(rep.getAlias());

        AuthenticatorConfigModel config = realm.addAuthenticatorConfig(RepresentationToModel.toModel(rep));
        return Response.created(keycloakContext.getUri().getAbsolutePathBuilder().path(config.getId()).build()).build();
    }

    /**
     * Get authenticator configuration
     *
     * @param id Configuration id
     */
    @Path("config/{id}")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public AuthenticatorConfigRepresentation getAuthenticatorConfig(@PathParam("id") String id) {
        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(id);
        if (config == null) {
            throw new NotFoundException("Could not find authenticator config");

        }
        return ModelToRepresentation.toRepresentation(config);
    }

    /**
     * Delete authenticator configuration
     *
     * @param id Configuration id
     */
    @Path("config/{id}")
    @DELETE
    @NoCache
    public void removeAuthenticatorConfig(@PathParam("id") String id) {
        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById(id);
        if (config == null) {
            throw new NotFoundException("Could not find authenticator config");

        }
        for (AuthenticationFlowModel flow : realm.getAuthenticationFlows()) {
            for (AuthenticationExecutionModel exe : realm.getAuthenticationExecutions(flow.getId())) {
                if (id.equals(exe.getAuthenticatorConfig())) {
                    exe.setAuthenticatorConfig(null);
                    realm.updateAuthenticatorExecution(exe);
                }
            }
        }

        realm.removeAuthenticatorConfig(config);
    }

    /**
     * Update authenticator configuration
     *
     * @param id  Configuration id
     * @param rep JSON describing new state of authenticator configuration
     */
    @Path("config/{id}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @NoCache
    public void updateAuthenticatorConfig(@PathParam("id") String id, AuthenticatorConfigRepresentation rep) {
        ReservedCharValidator.validate(rep.getAlias());
        AuthenticatorConfigModel exists = realm.getAuthenticatorConfigById(id);
        if (exists == null) {
            throw new NotFoundException("Could not find authenticator config");
        }

        exists.setAlias(rep.getAlias());
        exists.setConfig(RepresentationToModel.removeEmptyString(rep.getConfig()));
        realm.updateAuthenticatorConfig(exists);
    }
}
