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
package org.keycloak.services.resources.account.resources;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.store.PermissionTicketStore;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.Auth;
import org.keycloak.utils.MediaType;

import javax.ws.rs.*;
import javax.ws.rs.core.Link;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourcesService extends AbstractResourceService {

    public ResourcesService(KeycloakSession session, UserModel user, Auth auth, HttpRequest request) {
        super(session, user, auth, request);
    }

    /**
     * Returns a list of {@link Resource} where the {@link #user} is the resource owner.
     *
     * @param first the first result
     * @param max   the max result
     * @return a list of {@link Resource} where the {@link #user} is the resource owner
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response getResources(@QueryParam("name") String name,
                                 @QueryParam("first") Integer first,
                                 @QueryParam("max") Integer max) {
        Map<String, String[]> filters = new HashMap<>();

        filters.put("owner", new String[]{user.getId()});

        if (name != null) {
            filters.put("name", new String[]{name});
        }

        return queryResponse((f, m) -> resourceStore.findByResourceServer(filters, null, f, m).stream()
                .map(resource -> new Resource(resource, user, provider)), first, max);
    }

    /**
     * Returns a list of {@link Resource} shared with the {@link #user}
     *
     * @param first the first result
     * @param max   the max result
     * @return a list of {@link Resource} shared with the {@link #user}
     */
    @GET
    @Path("shared-with-me")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedWithMe(@QueryParam("name") String name,
                                    @QueryParam("first") Integer first,
                                    @QueryParam("max") Integer max) {
        return queryResponse((f, m) -> toPermissions(ticketStore.findGrantedResources(auth.getUser().getId(), name, f, m), false)
                .stream(), first, max);
    }

    /**
     * Returns a list of {@link Resource} where the {@link #user} is the resource owner and the resource is
     * shared with other users.
     *
     * @param first the first result
     * @param max   the max result
     * @return a list of {@link Resource} where the {@link #user} is the resource owner and the resource is
     * * shared with other users
     */
    @GET
    @Path("shared-with-others")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedWithOthers(@QueryParam("first") Integer first, @QueryParam("max") Integer max) {
        return queryResponse(
                (f, m) -> toPermissions(ticketStore.findGrantedOwnerResources(auth.getUser().getId(), f, m), true)
                        .stream(), first, max);
    }

    @Path("{id}")
    public Object getResource(@PathParam("id") String id) {
        org.keycloak.authorization.model.Resource resource = resourceStore.findById(id, null);

        if (resource == null) {
            throw new NotFoundException("resource_not_found");
        }

        if (!resource.getOwner().equals(user.getId())) {
            throw new BadRequestException("invalid_resource");
        }

        return new ResourceService(resource, provider.getKeycloakSession(), user, auth, request);
    }

    private Collection<ResourcePermission> toPermissions(List<org.keycloak.authorization.model.Resource> resources, boolean withRequesters) {
        Collection<ResourcePermission> permissions = new ArrayList<>();
        PermissionTicketStore ticketStore = provider.getStoreFactory().getPermissionTicketStore();

        for (org.keycloak.authorization.model.Resource resource : resources) {
            ResourcePermission permission = new ResourcePermission(resource, provider);

            List<PermissionTicket> tickets;

            if (withRequesters) {
                Map<String, String> filters = new HashMap<>();

                filters.put(PermissionTicket.OWNER, user.getId());
                filters.put(PermissionTicket.GRANTED, Boolean.TRUE.toString());
                filters.put(PermissionTicket.RESOURCE, resource.getId());

                tickets = ticketStore.find(filters, null, -1, -1);
            } else {
                tickets = ticketStore.findGranted(resource.getName(), user.getId(), null);
            }

            for (PermissionTicket ticket : tickets) {
                if (resource.equals(ticket.getResource())) {
                    if (withRequesters) {
                        Permission user = permission.getPermission(ticket.getRequester());

                        if (user == null) {
                            permission.addPermission(ticket.getRequester(),
                                    user = new Permission(ticket.getRequester(), provider));
                        }

                        user.addScope(ticket.getScope().getName());
                    } else {
                        permission.addScope(new Scope(ticket.getScope()));
                    }
                }
            }

            permissions.add(permission);
        }

        return permissions;
    }

    private Response queryResponse(BiFunction<Integer, Integer, Stream<?>> query, Integer first, Integer max) {
        if (first != null && max != null) {
            List result = query.apply(first, max + 1).collect(Collectors.toList());
            int size = result.size();

            if (size > max) {
                result = result.subList(0, size - 1);
            }

            return cors(Response.ok().entity(result).links(createPageLinks(first, max, size)));
        }

        return cors(Response.ok().entity(query.apply(-1, -1).collect(Collectors.toList())));
    }

    private Link[] createPageLinks(Integer first, Integer max, int resultSize) {
        if (resultSize == 0 || (first == 0 && resultSize <= max)) {
            return new Link[]{};
        }

        List<Link> links = new ArrayList();
        boolean nextPage = resultSize > max;

        if (nextPage) {
            links.add(Link.fromUri(
                    KeycloakUriBuilder.fromUri(request.getUri().getRequestUri()).replaceQuery("first={first}&max={max}")
                            .build(first + max, max))
                    .rel("next").build());
        }

        if (first > 0) {
            links.add(Link.fromUri(
                    KeycloakUriBuilder.fromUri(request.getUri().getRequestUri()).replaceQuery("first={first}&max={max}")
                            .build(nextPage ? first : first - max, max))
                    .rel("prev").build());
        }

        return links.toArray(new Link[links.size()]);
    }
}
