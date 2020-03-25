package org.keycloak.web.rs;

import org.keycloak.common.util.Resteasy;
import org.keycloak.services.error.KeycloakErrorHandler;
import org.keycloak.services.filters.KeycloakTransactionCommitter;
import org.keycloak.services.resources.*;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.util.ObjectMapperResolver;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

@ApplicationPath(value = "/auth")
public class KeycloakRsApplication extends Application {
    protected Set<Object> singletons = new HashSet<>();
    protected Set<Class<?>> classes = new HashSet<>();

    public KeycloakRsApplication() {
        singletons.add(new RobotsResource());
        singletons.add(new RealmsResource());
        singletons.add(new AdminRoot());
        classes.add(ThemeResource.class);
        classes.add(JsResource.class);

        classes.add(KeycloakTransactionCommitter.class);
        classes.add(KeycloakErrorHandler.class);

        singletons.add(new ObjectMapperResolver(Boolean.parseBoolean(System.getProperty("keycloak.jsonPrettyPrint", "false"))));
        singletons.add(new WelcomeResource());
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }
}
