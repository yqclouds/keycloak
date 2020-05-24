package org.keycloak.protocol.oidc.ext;

import org.keycloak.Config;
import org.keycloak.provider.ProviderFactory;

public interface OIDCExtProviderFactory extends ProviderFactory<OIDCExtProvider> {

    @Override
    default void init(Config.Scope config) {

    }

    @Override
    default void postInit() {

    }

    @Override
    default void close() {

    }

    @Override
    default int order() {
        return 0;
    }

}
