package org.keycloak.vault;

import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    @Value("${dir}")
    private String vaultDirectory;
    private Path vaultPath;

    @Override
    public VaultProvider create() {
        if (vaultDirectory == null) {
            LOG.debug("Can not create a vault since it's not initialized correctly");
            return null;
        }
        return new FilesPlainTextVaultProvider(vaultPath, getRealmName(), super.keyResolvers);
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();

        if (vaultDirectory == null) {
            LOG.debug("PlainTextVaultProviderFactory not configured");
            return;
        }

        vaultPath = Paths.get(vaultDirectory);
        if (!Files.exists(vaultPath)) {
            throw new VaultNotFoundException("The " + vaultPath.toAbsolutePath().toString() + " directory doesn't exist");
        }

        LOG.debug("Configured PlainTextVaultProviderFactory with directory {}", vaultPath.toString());
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
