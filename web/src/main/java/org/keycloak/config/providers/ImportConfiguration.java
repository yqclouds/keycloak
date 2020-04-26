package org.keycloak.config.providers;

import org.keycloak.exportimport.dir.DirImportProviderFactory;
import org.keycloak.exportimport.singlefile.SingleFileImportProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ImportConfiguration {
    @Bean
    public DirImportProviderFactory dirImportProviderFactory() {
        return new DirImportProviderFactory();
    }

    @Bean
    public SingleFileImportProviderFactory singleFileImportProviderFactory() {
        return new SingleFileImportProviderFactory();
    }
}
