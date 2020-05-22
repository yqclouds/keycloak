package org.keycloak.credential.hash;

import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * Provider factory for SHA512 variant of the PBKDF2 password hash algorithm.
 *
 * @author @author <a href="mailto:abkaplan07@gmail.com">Adam Kaplan</a>
 */
@Component("Pbkdf2Sha512PasswordHashProviderFactory")
@ProviderFactory(id = "pbkdf2-sha512", providerClasses = PasswordHashProvider.class)
public class Pbkdf2Sha512PasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "pbkdf2-sha512";

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";

    public static final int DEFAULT_ITERATIONS = 30000;

    @Override
    public PasswordHashProvider create() {
        return new Pbkdf2PasswordHashProvider(ID, PBKDF2_ALGORITHM, DEFAULT_ITERATIONS);
    }

    @Override
    public String getId() {
        return ID;
    }
}
