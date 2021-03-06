/*
 * Copyright 2017 Analytical Graphics, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.services.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 4/4/2017
 */

public abstract class AbstractClientCertificateFromHttpHeadersLookupFactory implements X509ClientCertificateLookupFactory {
    protected final static String CERTIFICATE_CHAIN_LENGTH = "certificateChainLength";
    protected final static String HTTP_HEADER_CLIENT_CERT = "sslClientCert";
    protected final static String HTTP_HEADER_CERT_CHAIN_PREFIX = "sslCertChainPrefix";
    private final static Logger LOG = LoggerFactory.getLogger(AbstractClientCertificateFromHttpHeadersLookupFactory.class);

    @Value("${sslClientCert}")
    public String sslClientCertHttpHeader = "";
    @Value("${sslCertChainPrefix}")
    public String sslChainHttpHeaderPrefix = "";
    @Value("${certificateChainLength}")
    public int certificateChainLength = 1;
}
