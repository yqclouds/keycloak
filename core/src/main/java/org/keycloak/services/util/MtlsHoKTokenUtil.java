package org.keycloak.services.util;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.util.Base64Url;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class MtlsHoKTokenUtil {
    // KEYCLOAK-6771 Certificate Bound Token
    // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3.1

    public static final String CERT_VERIFY_ERROR_DESC = "Client certificate missing, or its thumbprint and one in the refresh token did NOT match";
    protected static final Logger LOG = LoggerFactory.getLogger(MtlsHoKTokenUtil.class);
    private static final String DIGEST_ALG = "SHA-256";

    public AccessToken.CertConf bindTokenWithClientCertificate(HttpRequest request, KeycloakSession session) {
        X509Certificate[] certs = getCertificateChain(request, session);

        if (certs == null || certs.length < 1) {
            LOG.warn("no client certificate available.");
            return null;
        }

        String DERX509Base64UrlEncoded = null;
        try {
            // On Certificate Chain, first entry is considered to be client certificate.
            DERX509Base64UrlEncoded = getCertificateThumbprintInSHA256DERX509Base64UrlEncoded(certs[0]);
            if (LOG.isTraceEnabled()) dumpCertInfo(certs);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            // give up issuing MTLS HoK Token
            LOG.warn("give up issuing hok token. {}", e);
            return null;
        }

        AccessToken.CertConf certConf = new AccessToken.CertConf();
        certConf.setCertThumbprint(DERX509Base64UrlEncoded);
        return certConf;
    }

    public boolean verifyTokenBindingWithClientCertificate(AccessToken token, HttpRequest request, KeycloakSession session) {
        if (token == null) {
            LOG.warn("token is null");
            return false;
        }

        // Bearer Token, not MTLS HoK Token
        if (token.getCertConf() == null) {
            LOG.warn("bearer token received instead of hok token.");
            return false;
        }

        X509Certificate[] certs = getCertificateChain(request, session);

        // HoK Token, but no Client Certificate available
        if (certs == null || certs.length < 1) {
            LOG.warn("missing client certificate.");
            return false;
        }

        String DERX509Base64UrlEncoded = null;
        String x5ts256 = token.getCertConf().getCertThumbprint();
        LOG.trace("hok token cnf-x5t#s256 = {}", x5ts256);

        try {
            // On Certificate Chain, first entry is considered to be client certificate.
            DERX509Base64UrlEncoded = getCertificateThumbprintInSHA256DERX509Base64UrlEncoded(certs[0]);
            if (LOG.isTraceEnabled()) dumpCertInfo(certs);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            LOG.warn("client certificate exception. {}", e);
            return false;
        }

        if (!MessageDigest.isEqual(x5ts256.getBytes(), DERX509Base64UrlEncoded.getBytes())) {
            LOG.warn("certificate's thumbprint and one in the refresh token did not match.");
            return false;
        }

        return true;
    }

    @Autowired(required = false)
    private X509ClientCertificateLookup x509ClientCertificateLookup;

    private X509Certificate[] getCertificateChain(HttpRequest request, KeycloakSession session) {
        try {
            // Get a x509 client certificate
            if (x509ClientCertificateLookup == null) {
                LOG.error("\"{}\" Spi is not available, did you forget to update the configuration?", X509ClientCertificateLookup.class);
                return null;
            }
            X509Certificate[] certs = x509ClientCertificateLookup.getCertificateChain(request);
            return certs;
        } catch (GeneralSecurityException e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    private static String getCertificateThumbprintInSHA256DERX509Base64UrlEncoded(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        // need to calculate over DER encoding of the X.509 certificate
        //   https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3.1
        // in order to do that, call getEncoded()
        //   https://docs.oracle.com/javase/8/docs/api/java/security/cert/Certificate.html#getEncoded--
        byte[] DERX509Hash = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance(DIGEST_ALG);
        md.update(DERX509Hash);
        String DERX509Base64UrlEncoded = Base64Url.encode(md.digest());
        return DERX509Base64UrlEncoded;
    }

    private static void dumpCertInfo(X509Certificate[] certs) throws CertificateEncodingException {
        LOG.trace(":: Try Holder of Key Token");
        LOG.trace(":: # of x509 Client Certificate in Certificate Chain = %d", certs.length);
        for (int i = 0; i < certs.length; i++) {
            LOG.trace(":: certs[%d] Raw Bytes Counts of first x509 Client Certificate in Certificate Chain = %d", i, certs[i].toString().length());
            LOG.trace(":: certs[%d] Raw Bytes String of first x509 Client Certificate in Certificate Chain = {}", i, certs[i].toString());
            LOG.trace(":: certs[%d] DER Dump Bytes of first x509 Client Certificate in Certificate Chain = %d", i, certs[i].getEncoded().length);
            String DERX509Base64UrlEncoded = null;
            try {
                DERX509Base64UrlEncoded = getCertificateThumbprintInSHA256DERX509Base64UrlEncoded(certs[i]);
            } catch (Exception e) {
            }
            LOG.trace(":: certs[%d] Base64URL Encoded SHA-256 Hash of DER formatted first x509 Client Certificate in Certificate Chain = {}", i, DERX509Base64UrlEncoded);
            LOG.trace(":: certs[%d] DER Dump Bytes of first x509 Client Certificate TBScertificate in Certificate Chain = %d", i, certs[i].getTBSCertificate().length);
            LOG.trace(":: certs[%d] Signature Algorithm of first x509 Client Certificate in Certificate Chain = {}", i, certs[i].getSigAlgName());
            LOG.trace(":: certs[%d] Certfication Type of first x509 Client Certificate in Certificate Chain = {}", i, certs[i].getType());
            LOG.trace(":: certs[%d] Issuer DN of first x509 Client Certificate in Certificate Chain = {}", i, certs[i].getIssuerDN().getName());
            LOG.trace(":: certs[%d] Subject DN of first x509 Client Certificate in Certificate Chain = {}", i, certs[i].getSubjectDN().getName());
        }
    }
}
