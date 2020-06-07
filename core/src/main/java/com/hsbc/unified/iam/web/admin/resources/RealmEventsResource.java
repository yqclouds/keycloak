package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.constants.Constants;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.EventModel;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.representations.idm.RealmEventsConfigRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/events",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmEventsResource {
    private static final Logger LOG = LoggerFactory.getLogger(RealmEventsResource.class);

    protected AdminPermissionEvaluator auth;
    protected RealmModel realm;
    @Autowired
    private EventStoreProvider eventStoreProvider;

    public RealmEventsResource(AdminPermissionEvaluator auth, RealmModel realm) {
        this.auth = auth;
        this.realm = realm;
    }

    /**
     * Get events
     * <p>
     * Returns all events, or filters them based on URL query parameters listed here
     *
     * @param types       The types of events to return
     * @param client      App or oauth client name
     * @param user        User id
     * @param ipAddress   IP address
     * @param dateTo      To date
     * @param dateFrom    From date
     * @param firstResult Paging offset
     * @param maxResults  Maximum results size (defaults to 100)
     */
    @Path("events")
    @GET
    @NoCache
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public List<EventRepresentation> getEvents(@QueryParam("type") List<String> types, @QueryParam("client") String client,
                                               @QueryParam("user") String user, @QueryParam("dateFrom") String dateFrom, @QueryParam("dateTo") String dateTo,
                                               @QueryParam("ipAddress") String ipAddress, @QueryParam("first") Integer firstResult,
                                               @QueryParam("max") Integer maxResults) {
        auth.realm().requireViewEvents();

        EventQuery query = eventStoreProvider.createQuery().realm(realm.getId());
        if (client != null) {
            query.client(client);
        }

        if (types != null && !types.isEmpty()) {
            EventType[] t = new EventType[types.size()];
            for (int i = 0; i < t.length; i++) {
                t[i] = EventType.valueOf(types.get(i));
            }
            query.type(t);
        }

        if (user != null) {
            query.user(user);
        }

        if (dateFrom != null) {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
            Date from;
            try {
                from = df.parse(dateFrom);
            } catch (ParseException e) {
                throw new BadRequestException("Invalid value for 'Date(From)', expected format is yyyy-MM-dd");
            }
            query.fromDate(from);
        }

        if (dateTo != null) {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
            Date to;
            try {
                to = df.parse(dateTo);
            } catch (ParseException e) {
                throw new BadRequestException("Invalid value for 'Date(To)', expected format is yyyy-MM-dd");
            }
            query.toDate(to);
        }

        if (ipAddress != null) {
            query.ipAddress(ipAddress);
        }
        if (firstResult != null) {
            query.firstResult(firstResult);
        }
        if (maxResults != null) {
            query.maxResults(maxResults);
        } else {
            query.maxResults(Constants.DEFAULT_MAX_RESULTS);
        }

        return toEventListRep(query.getResultList());
    }

    private List<EventRepresentation> toEventListRep(List<EventModel> events) {
        List<EventRepresentation> reps = new ArrayList<>();
        for (EventModel event : events) {
            reps.add(ModelToRepresentation.toRepresentation(event));
        }
        return reps;
    }

    /**
     * Get the events provider configuration
     * <p>
     * Returns JSON object with events provider configuration
     */
    @GET
    @NoCache
    @Path("events/config")
    @Produces(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public RealmEventsConfigRepresentation getRealmEventsConfig() {
        auth.realm().requireViewEvents();

        RealmEventsConfigRepresentation config = ModelToRepresentation.toEventsConfigReprensetation(realm);
        if (config.getEnabledEventTypes() == null || config.getEnabledEventTypes().isEmpty()) {
            config.setEnabledEventTypes(new LinkedList<>());
            for (EventType e : EventType.values()) {
                if (e.isSaveByDefault()) {
                    config.getEnabledEventTypes().add(e.name());
                }
            }
        }
        return config;
    }

    /**
     * Update the events provider
     * <p>
     * Change the events provider and/or its configuration
     */
    @PUT
    @Path("events/config")
    @Consumes(javax.ws.rs.core.MediaType.APPLICATION_JSON)
    public void updateRealmEventsConfig(final RealmEventsConfigRepresentation rep) {
        auth.realm().requireManageEvents();

        LOG.debug("updating realm events config: " + realm.getName());
        new RealmFacadeImpl().updateRealmEventsConfig(rep, realm);
    }

    /**
     * Delete all events
     */
    @Path("events")
    @DELETE
    public void clearEvents() {
        auth.realm().requireManageEvents();

        eventStoreProvider.clear(realm.getId());
    }
}
