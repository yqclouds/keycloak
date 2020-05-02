package org.keycloak.vault;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.lang.invoke.MethodHandles;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Creates and configures {@link FilesPlainTextVaultProvider}.
 *
 * @author Sebastian Łaskawiec
 */
@Component("FilesPlainTextVaultProviderFactory")
@ProviderFactory(id = "files-plaintext", providerClasses = VaultProvider.class)
public class FilesPlainTextVaultProviderFactory extends AbstractVaultProviderFactory {

    public static final String PROVIDER_ID = "files-plaintext";
    private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());
    @Value("${dir}")
    private String vaultDirectory;
    private Path vaultPath;

    @Override
    public VaultProvider create(KeycloakSession session) {
        if (vaultDirectory == null) {
            logger.debug("Can not create a vault since it's not initialized correctly");
            return null;
        }
        return new FilesPlainTextVaultProvider(vaultPath, getRealmName(session), super.keyResolvers);
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();

        if (vaultDirectory == null) {
            logger.debug("PlainTextVaultProviderFactory not configured");
            return;
        }

        vaultPath = Paths.get(vaultDirectory);
        if (!Files.exists(vaultPath)) {
            throw new VaultNotFoundException("The " + vaultPath.toAbsolutePath().toString() + " directory doesn't exist");
        }

        logger.debugf("Configured PlainTextVaultProviderFactory with directory %s", vaultPath.toString());
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
