package org.keycloak.config.providers;

import org.keycloak.theme.FolderThemeProviderFactory;
import org.keycloak.theme.JarThemeProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ThemeConfiguration {
//    @Bean
//    public ClasspathThemeProviderFactory classpathThemeProviderFactory() {
//        return new ClasspathThemeProviderFactory();
//    }

    @Bean
    public JarThemeProviderFactory jarThemeProviderFactory() {
        return new JarThemeProviderFactory();
    }

    @Bean
    public FolderThemeProviderFactory folderThemeProviderFactory() {
        return new FolderThemeProviderFactory();
    }
}
