package org.keycloak.credential.hash;

import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * PBKDF2 Password Hash provider with HMAC using SHA256
 *
 * @author <a href"mailto:abkaplan07@gmail.com">Adam Kaplan</a>
 */
@Component("Pbkdf2Sha256PasswordHashProviderFactory")
@ProviderFactory(id = "pbkdf2-sha256", providerClasses = PasswordHashProvider.class)
public class Pbkdf2Sha256PasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "pbkdf2-sha256";

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static final int DEFAULT_ITERATIONS = 27500;

    @Override
    public PasswordHashProvider create() {
        return new Pbkdf2PasswordHashProvider(ID, PBKDF2_ALGORITHM, DEFAULT_ITERATIONS);
    }

    @Override
    public String getId() {
        return ID;
    }
}
