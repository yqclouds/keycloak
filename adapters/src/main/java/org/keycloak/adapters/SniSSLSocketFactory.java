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

package org.keycloak.adapters;

import org.apache.http.HttpHost;
import org.apache.http.conn.scheme.HostNameResolver;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:mstrukel@redhat.com">Marko Strukelj</a>
 */
public class SniSSLSocketFactory extends SSLSocketFactory {

    private static final Logger LOG = LoggerFactory.getLogger(SniSSLSocketFactory.class.getName());
    private static final AtomicBoolean skipSNIApplication = new AtomicBoolean(false);

    public SniSSLSocketFactory(String algorithm, KeyStore keystore, String keyPassword, KeyStore truststore, SecureRandom random, HostNameResolver nameResolver) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(algorithm, keystore, keyPassword, truststore, random, nameResolver);
    }

    public SniSSLSocketFactory(String algorithm, KeyStore keystore, String keyPassword, KeyStore truststore, SecureRandom random, TrustStrategy trustStrategy, X509HostnameVerifier hostnameVerifier) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(algorithm, keystore, keyPassword, truststore, random, trustStrategy, hostnameVerifier);
    }

    public SniSSLSocketFactory(String algorithm, KeyStore keystore, String keyPassword, KeyStore truststore, SecureRandom random, X509HostnameVerifier hostnameVerifier) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(algorithm, keystore, keyPassword, truststore, random, hostnameVerifier);
    }

    public SniSSLSocketFactory(KeyStore keystore, String keystorePassword, KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, keystorePassword, truststore);
    }

    public SniSSLSocketFactory(KeyStore keystore, String keystorePassword) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(keystore, keystorePassword);
    }

    public SniSSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(truststore);
    }

    public SniSSLSocketFactory(TrustStrategy trustStrategy, X509HostnameVerifier hostnameVerifier) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(trustStrategy, hostnameVerifier);
    }

    public SniSSLSocketFactory(TrustStrategy trustStrategy) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(trustStrategy);
    }

    public SniSSLSocketFactory(SSLContext sslContext) {
        super(sslContext);
    }

    public SniSSLSocketFactory(SSLContext sslContext, HostNameResolver nameResolver) {
        super(sslContext, nameResolver);
    }

    public SniSSLSocketFactory(SSLContext sslContext, X509HostnameVerifier hostnameVerifier) {
        super(sslContext, hostnameVerifier);
    }

    public SniSSLSocketFactory(SSLContext sslContext, String[] supportedProtocols, String[] supportedCipherSuites, X509HostnameVerifier hostnameVerifier) {
        super(sslContext, supportedProtocols, supportedCipherSuites, hostnameVerifier);
    }

    public SniSSLSocketFactory(javax.net.ssl.SSLSocketFactory socketfactory, X509HostnameVerifier hostnameVerifier) {
        super(socketfactory, hostnameVerifier);
    }

    public SniSSLSocketFactory(javax.net.ssl.SSLSocketFactory socketfactory, String[] supportedProtocols, String[] supportedCipherSuites, X509HostnameVerifier hostnameVerifier) {
        super(socketfactory, supportedProtocols, supportedCipherSuites, hostnameVerifier);
    }

    @Override
    public Socket connectSocket(int connectTimeout, Socket socket, HttpHost host, InetSocketAddress remoteAddress, InetSocketAddress localAddress, HttpContext context) throws IOException {
        return super.connectSocket(connectTimeout, applySNI(socket, host.getHostName()), host, remoteAddress, localAddress, context);
    }

    @Override
    public Socket createLayeredSocket(Socket socket, String target, int port, HttpContext context) throws IOException {
        return super.createLayeredSocket(applySNI(socket, target), target, port, context);
    }

    private Socket applySNI(final Socket socket, String hostname) {
        if (skipSNIApplication.get()) {
            LOG.info("Skipping application of SNI because JDK is missing setHost() method.");
            return socket;
        }

        if (socket instanceof SSLSocket) {
            try {
                Method setHostMethod = AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {
                    @Override
                    public Method run() throws NoSuchMethodException {
                        return socket.getClass().getMethod("setHost", String.class);
                    }
                });

                setHostMethod.invoke(socket, hostname);
                LOG.info("Applied SNI to socket for host {}", hostname);
            } catch (PrivilegedActionException e) {
                if (e.getCause() instanceof NoSuchMethodException) {
                    // For IBM java there is no method with name setHost(), however we don't need to applySNI
                    // because IBM java is doing it automatically, so we can set lower level of this message
                    // See: KEYCLOAK-6817
                    LOG.error("Failed to apply SNI to SSLSocket", e);
                    skipSNIApplication.set(true);
                } else {
                    LOG.warn("Failed to apply SNI to SSLSocket", e);
                }
            } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                LOG.warn("Failed to apply SNI to SSLSocket", e);
            }
        }
        return socket;
    }
}