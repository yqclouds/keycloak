package org.keycloak.credential.hash;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;

/**
 * PBKDF2 Password Hash provider with HMAC using SHA256
 *
 * @author <a href"mailto:abkaplan07@gmail.com">Adam Kaplan</a>
 */
@ProviderFactory(id = "pbkdf2-sha256")
public class Pbkdf2Sha256PasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "pbkdf2-sha256";

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static final int DEFAULT_ITERATIONS = 27500;

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new Pbkdf2PasswordHashProvider(ID, PBKDF2_ALGORITHM, DEFAULT_ITERATIONS);
    }

    @Override
    public String getId() {
        return ID;
    }
}
