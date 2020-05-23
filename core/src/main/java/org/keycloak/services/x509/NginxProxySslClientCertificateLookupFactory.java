package org.keycloak.services.x509;

import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * The factory and the corresponding providers extract a client certificate
 * from a NGINX reverse proxy (TLS termination).
 *
 * @author <a href="mailto:arnault.michel@toad-consulting.com">Arnault MICHEL</a>
 * @version $Revision: 1 $
 * @since 10/09/2018
 */
@Component("NginxProxySslClientCertificateLookupFactory")
@ProviderFactory(id = "nginx", providerClasses = X509ClientCertificateLookup.class)
public class NginxProxySslClientCertificateLookupFactory extends AbstractClientCertificateFromHttpHeadersLookupFactory {

    private final static String PROVIDER = "nginx";

    @Override
    public X509ClientCertificateLookup create() {
        return new NginxProxySslClientCertificateLookup(sslClientCertHttpHeader, sslChainHttpHeaderPrefix, certificateChainLength);
    }

    @Override
    public String getId() {
        return PROVIDER;
    }
}
