package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.constants.Constants;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEventModel;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.AdminEventRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.QueryParam;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping(
        value = "/admin/realms/{realm}/admin-events",
        consumes = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE},
        produces = {org.springframework.http.MediaType.APPLICATION_JSON_VALUE}
)
@PreAuthorize("hasPermission({'master', 'admin'})")
public class RealmAdminEventsResource {
    @Autowired
    private AdminPermissionEvaluator auth;
    @Autowired
    private RealmModel realm;
    @Autowired
    private EventStoreProvider eventStoreProvider;

    /**
     * Get admin events
     * <p>
     * Returns all admin events, or filters events based on URL query parameters listed here
     */
    @RequestMapping(method = RequestMethod.GET)
    public List<AdminEventRepresentation> getEvents(@QueryParam("operationTypes") List<String> operationTypes,
                                                    @QueryParam("authRealm") String authRealm,
                                                    @QueryParam("authClient") String authClient,
                                                    @QueryParam("authUser") String authUser,
                                                    @QueryParam("authIpAddress") String authIpAddress,
                                                    @QueryParam("resourcePath") String resourcePath,
                                                    @QueryParam("dateFrom") String dateFrom,
                                                    @QueryParam("dateTo") String dateTo,
                                                    @QueryParam("first") Integer firstResult,
                                                    @QueryParam("max") Integer maxResults,
                                                    @QueryParam("resourceTypes") List<String> resourceTypes) {
        auth.realm().requireViewEvents();

        AdminEventQuery query = eventStoreProvider.createAdminQuery().realm(realm.getId());

        if (authRealm != null) {
            query.authRealm(authRealm);
        }

        if (authClient != null) {
            query.authClient(authClient);
        }

        if (authUser != null) {
            query.authUser(authUser);
        }

        if (authIpAddress != null) {
            query.authIpAddress(authIpAddress);
        }

        if (resourcePath != null) {
            query.resourcePath(resourcePath);
        }

        if (operationTypes != null && !operationTypes.isEmpty()) {
            OperationType[] t = new OperationType[operationTypes.size()];
            for (int i = 0; i < t.length; i++) {
                t[i] = OperationType.valueOf(operationTypes.get(i));
            }
            query.operation(t);
        }

        if (resourceTypes != null && !resourceTypes.isEmpty()) {
            ResourceType[] t = new ResourceType[resourceTypes.size()];
            for (int i = 0; i < t.length; i++) {
                t[i] = ResourceType.valueOf(resourceTypes.get(i));
            }
            query.resourceType(t);
        }


        if (dateFrom != null) {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
            Date from = null;
            try {
                from = df.parse(dateFrom);
            } catch (ParseException e) {
                throw new BadRequestException("Invalid value for 'Date(From)', expected format is yyyy-MM-dd");
            }
            query.fromTime(from);
        }

        if (dateTo != null) {
            SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd");
            Date to = null;
            try {
                to = df.parse(dateTo);
            } catch (ParseException e) {
                throw new BadRequestException("Invalid value for 'Date(To)', expected format is yyyy-MM-dd");
            }
            query.toTime(to);
        }

        if (firstResult != null) {
            query.firstResult(firstResult);
        }
        if (maxResults != null) {
            query.maxResults(maxResults);
        } else {
            query.maxResults(Constants.DEFAULT_MAX_RESULTS);
        }

        return toAdminEventRep(query.getResultList());
    }

    private List<AdminEventRepresentation> toAdminEventRep(List<AdminEventModel> events) {
        List<AdminEventRepresentation> reps = new ArrayList<>();
        for (AdminEventModel event : events) {
            reps.add(ModelToRepresentation.toRepresentation(event));
        }

        return reps;
    }

    /**
     * Delete all admin events
     */
    @RequestMapping(method = RequestMethod.DELETE)
    public void clearAdminEvents() {
        auth.realm().requireManageEvents();

        eventStoreProvider.clearAdmin(realm.getId());
    }
}
