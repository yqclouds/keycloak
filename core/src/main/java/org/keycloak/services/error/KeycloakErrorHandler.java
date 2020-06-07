package org.keycloak.services.error;

import com.fasterxml.jackson.core.JsonParseException;
import org.jboss.resteasy.spi.Failure;
import org.keycloak.common.util.Resteasy;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.utils.MediaTypeMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import java.util.regex.Pattern;

@Provider
public class KeycloakErrorHandler implements ExceptionMapper<Throwable> {

    public static final String UNCAUGHT_SERVER_ERROR_TEXT = "Uncaught server error";
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakErrorHandler.class);
    private static final Pattern realmNamePattern = Pattern.compile(".*/realms/([^/]+).*");

    @Context
    private HttpHeaders headers;

    @Override
    public Response toResponse(Throwable throwable) {
        KeycloakTransaction tx = Resteasy.getContextData(KeycloakTransaction.class);
        tx.setRollbackOnly();

        int statusCode = getStatusCode(throwable);

        if (statusCode >= 500 && statusCode <= 599) {
            LOG.error(UNCAUGHT_SERVER_ERROR_TEXT, throwable);
        }

        if (!MediaTypeMatcher.isHtmlRequest(headers)) {
            OAuth2ErrorRepresentation error = new OAuth2ErrorRepresentation();

            error.setError(getErrorCode(throwable));

            return Response.status(statusCode)
                    .header(HttpHeaders.CONTENT_TYPE, javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE.toString())
                    .entity(error)
                    .build();
        }

        return null;
    }

    private int getStatusCode(Throwable throwable) {
        int status = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
        if (throwable instanceof WebApplicationException) {
            WebApplicationException ex = (WebApplicationException) throwable;
            status = ex.getResponse().getStatus();
        }
        if (throwable instanceof Failure) {
            Failure f = (Failure) throwable;
            status = f.getErrorCode();
        }
        if (throwable instanceof JsonParseException) {
            status = Response.Status.BAD_REQUEST.getStatusCode();
        }
        return status;
    }

    private String getErrorCode(Throwable throwable) {
        if (throwable instanceof WebApplicationException && throwable.getMessage() != null) {
            return throwable.getMessage();
        }

        return "unknown_error";
    }
}
