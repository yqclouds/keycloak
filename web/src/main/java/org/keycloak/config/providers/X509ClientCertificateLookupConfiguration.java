package org.keycloak.config.providers;

import org.keycloak.services.x509.ApacheProxySslClientCertificateLookupFactory;
import org.keycloak.services.x509.DefaultClientCertificateLookupFactory;
import org.keycloak.services.x509.HaProxySslClientCertificateLookupFactory;
import org.keycloak.services.x509.NginxProxySslClientCertificateLookupFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class X509ClientCertificateLookupConfiguration {
    @Bean
    public NginxProxySslClientCertificateLookupFactory nginxProxySslClientCertificateLookupFactory() {
        return new NginxProxySslClientCertificateLookupFactory();
    }

    @Bean
    public DefaultClientCertificateLookupFactory defaultClientCertificateLookupFactory() {
        return new DefaultClientCertificateLookupFactory();
    }

    @Bean
    public ApacheProxySslClientCertificateLookupFactory apacheProxySslClientCertificateLookupFactory() {
        return new ApacheProxySslClientCertificateLookupFactory();
    }

    @Bean
    public HaProxySslClientCertificateLookupFactory haProxySslClientCertificateLookupFactory() {
        return new HaProxySslClientCertificateLookupFactory();
    }
}
