package org.keycloak.authentication;

/**
 * Implement this interface when declaring your required action factory
 * has support for multiple oidc display query parameter parameter types
 * if the display query parameter is set and your factory implements this interface, this method
 * will be called.
 */
public interface DisplayTypeRequiredActionFactory {
    RequiredActionProvider createDisplay(String displayType);
}
