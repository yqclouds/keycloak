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

package com.hsbc.unified.iam.web.admin.resources;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.plugins.providers.multipart.InputPart;
import org.jboss.resteasy.plugins.providers.multipart.MultipartFormDataInput;
import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.KeyStoreConfig;
import org.keycloak.representations.idm.CertificateRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.util.CertificateInfoHelper;
import org.keycloak.util.JWKSUtils;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * @resource Client Attribute Certificate
 */
public class RealmClientAttributeCertificateResource {

    public static final String CERTIFICATE_PEM = "Certificate PEM";
    public static final String PUBLIC_KEY_PEM = "Public Key PEM";
    public static final String JSON_WEB_KEY_SET = "JSON Web Key Set";

    protected RealmModel realm;
    protected ClientModel client;
    @Context
    protected KeycloakContext keycloakContext;
    protected String attributePrefix;

    public RealmClientAttributeCertificateResource(RealmModel realm, ClientModel client, String attributePrefix) {
        this.realm = realm;
        this.client = client;
        this.attributePrefix = attributePrefix;
    }

    /**
     * Get key info
     */
    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateRepresentation getKeyInfo() {
        return CertificateInfoHelper.getCertificateFromClient(client, attributePrefix);
    }

    /**
     * Generate a new certificate with new key pair
     */
    @POST
    @NoCache
    @Path("generate")
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateRepresentation generate() {
        CertificateRepresentation info = KeycloakModelUtils.generateKeyPairCertificate(client.getClientId());

        CertificateInfoHelper.updateClientModelCertificateInfo(client, info, attributePrefix);

        return info;
    }

    /**
     * Upload certificate and eventually private key
     */
    @POST
    @Path("upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateRepresentation uploadJks(MultipartFormDataInput input) throws IOException {
        try {
            CertificateRepresentation info = getCertFromRequest(input);
            CertificateInfoHelper.updateClientModelCertificateInfo(client, info, attributePrefix);

            return info;
        } catch (IllegalStateException ise) {
            throw new ErrorResponseException("certificate-not-found", "Certificate or key with given alias not found in the keystore", Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Upload only certificate, not private key
     */
    @POST
    @Path("upload-certificate")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateRepresentation uploadJksCertificate(MultipartFormDataInput input) throws IOException {
        try {
            CertificateRepresentation info = getCertFromRequest(input);
            info.setPrivateKey(null);
            CertificateInfoHelper.updateClientModelCertificateInfo(client, info, attributePrefix);

            return info;
        } catch (IllegalStateException ise) {
            throw new ErrorResponseException("certificate-not-found", "Certificate or key with given alias not found in the keystore", Response.Status.BAD_REQUEST);
        }
    }

    private CertificateRepresentation getCertFromRequest(MultipartFormDataInput input) throws IOException {
        CertificateRepresentation info = new CertificateRepresentation();
        Map<String, List<InputPart>> uploadForm = input.getFormDataMap();
        List<InputPart> keystoreFormatPart = uploadForm.get("keystoreFormat");
        if (keystoreFormatPart == null) throw new BadRequestException();
        String keystoreFormat = keystoreFormatPart.get(0).getBodyAsString();
        List<InputPart> inputParts = uploadForm.get("file");
        switch (keystoreFormat) {
            case CERTIFICATE_PEM: {
                String pem = StreamUtil.readString(inputParts.get(0).getBody(InputStream.class, null));

                pem = PemUtils.removeBeginEnd(pem);

                // Validate format
                KeycloakModelUtils.getCertificate(pem);

                info.setCertificate(pem);
                return info;
            }
            case PUBLIC_KEY_PEM: {
                String pem = StreamUtil.readString(inputParts.get(0).getBody(InputStream.class, null));

                // Validate format
                KeycloakModelUtils.getPublicKey(pem);

                info.setPublicKey(pem);
                return info;
            }
            case JSON_WEB_KEY_SET:
                InputStream stream = inputParts.get(0).getBody(InputStream.class, null);
                JSONWebKeySet keySet = JsonSerialization.readValue(stream, JSONWebKeySet.class);
                JWK publicKeyJwk = JWKSUtils.getKeyForUse(keySet, JWK.Use.SIG);
                if (publicKeyJwk == null) {
                    throw new IllegalStateException("Certificate not found for use sig");
                } else {
                    PublicKey publicKey = JWKParser.create(publicKeyJwk).toPublicKey();
                    String publicKeyPem = KeycloakModelUtils.getPemFromKey(publicKey);
                    info.setPublicKey(publicKeyPem);
                    info.setKid(publicKeyJwk.getKeyId());
                    return info;
                }
        }


        String keyAlias = uploadForm.get("keyAlias").get(0).getBodyAsString();
        List<InputPart> keyPasswordPart = uploadForm.get("keyPassword");
        char[] keyPassword = keyPasswordPart != null ? keyPasswordPart.get(0).getBodyAsString().toCharArray() : null;

        List<InputPart> storePasswordPart = uploadForm.get("storePassword");
        char[] storePassword = storePasswordPart != null ? storePasswordPart.get(0).getBodyAsString().toCharArray() : null;
        PrivateKey privateKey = null;
        X509Certificate certificate;
        try {
            KeyStore keyStore;
            if (keystoreFormat.equals("JKS")) keyStore = KeyStore.getInstance("JKS");
            else keyStore = KeyStore.getInstance(keystoreFormat, "BC");
            keyStore.load(inputParts.get(0).getBody(InputStream.class, null), storePassword);
            try {
                privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword);
            } catch (Exception e) {
                // ignore
            }
            certificate = (X509Certificate) keyStore.getCertificate(keyAlias);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        if (privateKey != null) {
            String privateKeyPem = KeycloakModelUtils.getPemFromKey(privateKey);
            info.setPrivateKey(privateKeyPem);
        }

        if (certificate != null) {
            String certPem = KeycloakModelUtils.getPemFromCertificate(certificate);
            info.setCertificate(certPem);
        }

        return info;
    }

    /**
     * Get a keystore file for the client, containing private key and public certificate
     *
     * @param config Keystore configuration as JSON
     */
    @POST
    @NoCache
    @Path("/download")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.APPLICATION_JSON)
    public byte[] getKeystore(final KeyStoreConfig config) {
        if (config.getFormat() != null && !config.getFormat().equals("JKS") && !config.getFormat().equals("PKCS12")) {
            throw new NotAcceptableException("Only support jks or pkcs12 format.");
        }

        CertificateRepresentation info = CertificateInfoHelper.getCertificateFromClient(client, attributePrefix);
        String privatePem = info.getPrivateKey();
        String certPem = info.getCertificate();

        if (privatePem == null && certPem == null) {
            throw new NotFoundException("keypair not generated for client");
        }
        if (privatePem != null && config.getKeyPassword() == null) {
            throw new ErrorResponseException("password-missing", "Need to specify a key password for jks download", Response.Status.BAD_REQUEST);
        }
        if (config.getStorePassword() == null) {
            throw new ErrorResponseException("password-missing", "Need to specify a store password for jks download", Response.Status.BAD_REQUEST);
        }

        return getKeystore(config, privatePem, certPem);
    }

    /**
     * Generate a new keypair and certificate, and get the private key file
     * <p>
     * Generates a keypair and certificate and serves the private key in a specified keystore format.
     * Only generated public certificate is saved in Keycloak DB - the private key is not.
     *
     * @param config Keystore configuration as JSON
     */
    @POST
    @NoCache
    @Path("/generate-and-download")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.APPLICATION_JSON)
    public byte[] generateAndGetKeystore(final KeyStoreConfig config) {
        if (config.getFormat() != null && !config.getFormat().equals("JKS") && !config.getFormat().equals("PKCS12")) {
            throw new NotAcceptableException("Only support jks or pkcs12 format.");
        }
        if (config.getKeyPassword() == null) {
            throw new ErrorResponseException("password-missing", "Need to specify a key password for jks generation and download", Response.Status.BAD_REQUEST);
        }
        if (config.getStorePassword() == null) {
            throw new ErrorResponseException("password-missing", "Need to specify a store password for jks generation and download", Response.Status.BAD_REQUEST);
        }

        CertificateRepresentation info = KeycloakModelUtils.generateKeyPairCertificate(client.getClientId());
        byte[] rtn = getKeystore(config, info.getPrivateKey(), info.getCertificate());

        info.setPrivateKey(null);

        CertificateInfoHelper.updateClientModelCertificateInfo(client, info, attributePrefix);

        return rtn;
    }

    @Autowired
    private KeyManager keyManager;

    private byte[] getKeystore(KeyStoreConfig config, String privatePem, String certPem) {
        try {
            String format = config.getFormat();
            KeyStore keyStore;
            if (format.equals("JKS")) keyStore = KeyStore.getInstance("JKS");
            else keyStore = KeyStore.getInstance(format, "BC");
            keyStore.load(null, null);
            String keyAlias = config.getKeyAlias();
            if (keyAlias == null) keyAlias = client.getClientId();
            if (privatePem != null) {
                PrivateKey privateKey = PemUtils.decodePrivateKey(privatePem);
                X509Certificate clientCert = PemUtils.decodeCertificate(certPem);


                Certificate[] chain = {clientCert};

                keyStore.setKeyEntry(keyAlias, privateKey, config.getKeyPassword().trim().toCharArray(), chain);
            } else {
                X509Certificate clientCert = PemUtils.decodeCertificate(certPem);
                keyStore.setCertificateEntry(keyAlias, clientCert);
            }


            if (config.isRealmCertificate() == null || config.isRealmCertificate()) {
                String kid = keyManager.getActiveRsaKey(realm).getKid();
                Certificate certificate = keyManager.getRsaCertificate(realm, kid);
                String certificateAlias = config.getRealmAlias();
                if (certificateAlias == null) certificateAlias = realm.getName();
                keyStore.setCertificateEntry(certificateAlias, certificate);
            }
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            keyStore.store(stream, config.getStorePassword().trim().toCharArray());
            stream.flush();
            stream.close();
            return stream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
