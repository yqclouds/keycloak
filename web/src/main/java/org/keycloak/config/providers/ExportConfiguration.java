package org.keycloak.config.providers;

import org.keycloak.exportimport.dir.DirExportProviderFactory;
import org.keycloak.exportimport.singlefile.SingleFileExportProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ExportConfiguration {
    @Bean
    public SingleFileExportProviderFactory singleFileExportProviderFactory() {
        return new SingleFileExportProviderFactory();
    }

    @Bean
    public DirExportProviderFactory dirExportProviderFactory() {
        return new DirExportProviderFactory();
    }
}
