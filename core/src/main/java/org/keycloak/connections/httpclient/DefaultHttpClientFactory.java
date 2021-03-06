/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.connections.httpclient;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.common.util.EnvUtil;
import org.keycloak.common.util.KeystoreUtil;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.truststore.TruststoreProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

/**
 * The default {@link HttpClientFactory} for {@link HttpClientProvider HttpClientProvider's} used by Keycloak for outbound HTTP calls.
 * <p>
 * The constructed clients can be configured via Keycloaks SPI configuration, e.g. {@code standalone.xml, standalone-ha.xml, domain.xml}.
 * </p>
 * <p>
 * Examples for jboss-cli
 * </p>
 * <pre>
 * {@code
 *
 * /subsystem=keycloak-server/spi=connectionsHttpClient/provider=default:add(enabled=true)
 * /subsystem=keycloak-server/spi=connectionsHttpClient/provider=default:write-attribute(name=properties.connection-pool-size,value=128)
 * /subsystem=keycloak-server/spi=connectionsHttpClient/provider=default:write-attribute(name=properties.proxy-mappings,value=[".*\\.(google|googleapis)\\.com;http://www-proxy.acme.corp.com:8080",".*\\.acme\\.corp\\.com;NO_PROXY",".*;http://fallback:8080"])
 * }
 * </pre>
 * </p>
 *
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("DefaultHttpClientFactory")
@ProviderFactory(id = "default", providerClasses = HttpClientProvider.class)
public class DefaultHttpClientFactory implements HttpClientFactory {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

    @Value("${socket-timeout-millis}")
    private long socketTimeout = -1L;
    @Value("${establish-connection-timeout-millis}")
    private long establishConnectionTimeout = -1L;
    @Value("${max-pooled-per-route}")
    private int maxPooledPerRoute = 64;
    @Value("${connection-pool-size}")
    private int connectionPoolSize = 128;
    @Value("${connection-ttl-millis}")
    private long connectionTTL = -1L;
    @Value("${max-connection-idle-time-millis}")
    private long maxConnectionIdleTime = 900000L;
    @Value("${disable-cookies}")
    private boolean disableCookies = true;
    @Value("${client-keystore}")
    private String clientKeystore;
    @Value("${client-keystore-password}")
    private String clientKeystorePassword;
    @Value("${client-key-password}")
    private String clientPrivateKeyPassword;
    @Value("${proxy-mappings}")
    private String[] proxyMappings;
    @Value("${disable-trust-manager}")
    private boolean disableTrustManager = false;

    private volatile CloseableHttpClient httpClient;

    @Override
    public HttpClientProvider create() {
        lazyInit();

        return new HttpClientProvider() {
            @Override
            public HttpClient getHttpClient() {
                return httpClient;
            }

            @Override
            public void close() {

            }

            @Override
            public int postText(String uri, String text) throws IOException {
                HttpPost request = new HttpPost(uri);
                request.setEntity(EntityBuilder.create().setText(text).setContentType(ContentType.TEXT_PLAIN).build());
                HttpResponse response = httpClient.execute(request);
                try {
                    return response.getStatusLine().getStatusCode();
                } finally {
                    HttpEntity entity = response.getEntity();
                    if (entity != null) {
                        InputStream is = entity.getContent();
                        if (is != null) is.close();
                    }

                }
            }

            @Override
            public InputStream get(String uri) throws IOException {
                HttpGet request = new HttpGet(uri);
                HttpResponse response = httpClient.execute(request);
                HttpEntity entity = response.getEntity();
                if (entity == null) return null;
                return entity.getContent();

            }
        };
    }

    @PreDestroy
    public void destroy() throws Exception {
        try {
            if (httpClient != null) {
                httpClient.close();
            }
        } catch (IOException e) {
        }
    }

    @Override
    public String getId() {
        return "default";
    }

    @Autowired(required = false)
    private TruststoreProvider truststoreProvider;

    private void lazyInit() {
        if (httpClient == null) {
            synchronized (this) {
                if (httpClient == null) {
                    HttpClientBuilder builder = new HttpClientBuilder();

                    builder.socketTimeout(socketTimeout, TimeUnit.MILLISECONDS)
                            .establishConnectionTimeout(establishConnectionTimeout, TimeUnit.MILLISECONDS)
                            .maxPooledPerRoute(maxPooledPerRoute)
                            .connectionPoolSize(connectionPoolSize)
                            .connectionTTL(connectionTTL, TimeUnit.MILLISECONDS)
                            .maxConnectionIdleTime(maxConnectionIdleTime, TimeUnit.MILLISECONDS)
                            .disableCookies(disableCookies)
                            .proxyMappings(ProxyMappings.valueOf(proxyMappings));

                    boolean disableTruststoreProvider = truststoreProvider == null || truststoreProvider.getTruststore() == null;

                    if (disableTruststoreProvider) {
                        LOG.warn("TruststoreProvider is disabled");
                    } else {
                        builder.hostnameVerification(HttpClientBuilder.HostnameVerificationPolicy.valueOf(truststoreProvider.getPolicy().name()));
                        try {
                            builder.trustStore(truststoreProvider.getTruststore());
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to load truststore", e);
                        }
                    }

                    if (disableTrustManager) {
                        LOG.warn("TrustManager is disabled");
                        builder.disableTrustManager();
                    }

                    if (clientKeystore != null) {
                        clientKeystore = EnvUtil.replace(clientKeystore);
                        try {
                            KeyStore clientCertKeystore = KeystoreUtil.loadKeyStore(clientKeystore, clientKeystorePassword);
                            builder.keyStore(clientCertKeystore, clientPrivateKeyPassword);
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to load keystore", e);
                        }
                    }
                    httpClient = builder.build();
                }
            }
        }
    }
}
