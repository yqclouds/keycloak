/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.x509;

import com.hsbc.unified.iam.core.constants.Constants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import com.hsbc.unified.iam.core.crypto.HashException;
import com.hsbc.unified.iam.core.crypto.JavaAlgorithm;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.security.auth.x500.X500Principal;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.function.Function;


/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/31/2016
 */

public abstract class AbstractX509ClientCertificateAuthenticator implements Authenticator {

    public static final String DEFAULT_ATTRIBUTE_NAME = "usercertificate";
    public static final String REGULAR_EXPRESSION = "x509-cert-auth.regular-expression";
    public static final String ENABLE_CRL = "x509-cert-auth.crl-checking-enabled";
    public static final String ENABLE_OCSP = "x509-cert-auth.ocsp-checking-enabled";
    public static final String ENABLE_CRLDP = "x509-cert-auth.crldp-checking-enabled";
    public static final String CANONICAL_DN = "x509-cert-auth.canonical-dn-enabled";
    public static final String TIMESTAMP_VALIDATION = "x509-cert-auth.timestamp-validation-enabled";
    public static final String SERIALNUMBER_HEX = "x509-cert-auth.serialnumber-hex-enabled";
    public static final String CRL_RELATIVE_PATH = "x509-cert-auth.crl-relative-path";
    public static final String OCSPRESPONDER_URI = "x509-cert-auth.ocsp-responder-uri";
    public static final String OCSPRESPONDER_CERTIFICATE = "x509-cert-auth.ocsp-responder-certificate";
    public static final String MAPPING_SOURCE_SELECTION = "x509-cert-auth.mapping-source-selection";
    public static final String MAPPING_SOURCE_CERT_SUBJECTDN = "Match SubjectDN using regular expression";
    public static final String MAPPING_SOURCE_CERT_SUBJECTDN_EMAIL = "Subject's e-mail";
    public static final String MAPPING_SOURCE_CERT_SUBJECTALTNAME_EMAIL = "Subject's Alternative Name E-mail";
    public static final String MAPPING_SOURCE_CERT_SUBJECTALTNAME_OTHERNAME = "Subject's Alternative Name otherName (UPN)";
    public static final String MAPPING_SOURCE_CERT_SUBJECTDN_CN = "Subject's Common Name";
    public static final String MAPPING_SOURCE_CERT_ISSUERDN = "Match IssuerDN using regular expression";
    public static final String MAPPING_SOURCE_CERT_SERIALNUMBER = "Certificate Serial Number";
    public static final String MAPPING_SOURCE_CERT_SHA256_THUMBPRINT = "SHA-256 Thumbprint";
    public static final String MAPPING_SOURCE_CERT_SERIALNUMBER_ISSUERDN = "Certificate Serial Number and IssuerDN";
    public static final String MAPPING_SOURCE_CERT_CERTIFICATE_PEM = "Full Certificate in PEM format";
    public static final String USER_MAPPER_SELECTION = "x509-cert-auth.mapper-selection";
    public static final String USER_ATTRIBUTE_MAPPER = "Custom Attribute Mapper";
    public static final String USERNAME_EMAIL_MAPPER = "Username or Email";
    public static final String CUSTOM_ATTRIBUTE_NAME = "x509-cert-auth.mapper-selection.user-attribute-name";
    public static final String CERTIFICATE_KEY_USAGE = "x509-cert-auth.keyusage";
    public static final String CERTIFICATE_EXTENDED_KEY_USAGE = "x509-cert-auth.extendedkeyusage";
    public static final String CONFIRMATION_PAGE_DISALLOWED = "x509-cert-auth.confirmation-page-disallowed";
    static final String DEFAULT_MATCH_ALL_EXPRESSION = "(.*?)(?:$)";

    protected static final Logger LOG = LoggerFactory.getLogger(AbstractX509ClientCertificateAuthenticator.class);

    @Autowired(required = false)
    private X509ClientCertificateLookup x509ClientCertificateLookup;

    protected Response createInfoResponse(AuthenticationFlowContext context, String infoMessage, Object... parameters) {
        LoginFormsProvider form = context.form();
        return form.setInfo(infoMessage, parameters).createInfoPage();
    }

    // The method is purely for purposes of facilitating the unit testing
    public CertificateValidator.CertificateValidatorBuilder certificateValidationParameters(X509AuthenticatorConfigModel config) throws Exception {
        return CertificateValidatorConfigBuilder.fromConfig(config);
    }

    @Override
    public void close() {

    }

    protected X509Certificate[] getCertificateChain(AuthenticationFlowContext context) {
        try {
            // Get a x509 client certificate
            if (x509ClientCertificateLookup == null) {
                LOG.error("\"{}\" Spi is not available, did you forget to update the configuration?",
                        X509ClientCertificateLookup.class.getName());
                return null;
            }

            X509Certificate[] certs = x509ClientCertificateLookup.getCertificateChain(context.getHttpRequest());

            if (certs != null) {
                for (X509Certificate cert : certs) {
                    LOG.trace("\"{}\"", cert.getSubjectDN().getName());
                }
            }

            return certs;
        } catch (GeneralSecurityException e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    // Saving some notes for audit to authSession as the event may not be necessarily triggered in this HTTP request where the certificate was parsed
    // For example if there is confirmation page enabled, it will be in the additional request
    protected void saveX509CertificateAuditDataToAuthSession(AuthenticationFlowContext context,
                                                             X509Certificate cert) {
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_SERIAL_NUMBER, cert.getSerialNumber().toString());
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME, cert.getSubjectDN().toString());
        context.getAuthenticationSession().setAuthNote(Details.X509_CERTIFICATE_ISSUER_DISTINGUISHED_NAME, cert.getIssuerDN().toString());
    }

    protected void recordX509CertificateAuditDataViaContextEvent(AuthenticationFlowContext context) {
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_SERIAL_NUMBER);
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
        recordX509DetailFromAuthSessionToEvent(context, Details.X509_CERTIFICATE_ISSUER_DISTINGUISHED_NAME);
    }

    private void recordX509DetailFromAuthSessionToEvent(AuthenticationFlowContext context, String detailName) {
        String detailValue = context.getAuthenticationSession().getAuthNote(detailName);
        context.getEvent().detail(detailName, detailValue);
    }

    // Purely for unit testing
    public UserIdentityExtractor getUserIdentityExtractor(X509AuthenticatorConfigModel config) {
        return UserIdentityExtractorBuilder.fromConfig(config);
    }

    @Autowired
    private UserIdentityToModelMapperBuilder userIdentityToModelMapperBuilder;

    // Purely for unit testing
    public UserIdentityToModelMapper getUserIdentityToModelMapper(X509AuthenticatorConfigModel config) {
        return userIdentityToModelMapperBuilder.fromConfig(config);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(RealmModel realm, UserModel user) {
    }

    protected static class CertificateValidatorConfigBuilder {

        static CertificateValidator.CertificateValidatorBuilder fromConfig(X509AuthenticatorConfigModel config) throws Exception {

            CertificateValidator.CertificateValidatorBuilder builder = new CertificateValidator.CertificateValidatorBuilder();
            return builder
                    .keyUsage()
                    .parse(config.getKeyUsage())
                    .extendedKeyUsage()
                    .parse(config.getExtendedKeyUsage())
                    .revocation()
                    .cRLEnabled(config.getCRLEnabled())
                    .cRLDPEnabled(config.getCRLDistributionPointEnabled())
                    .cRLrelativePath(config.getCRLRelativePath())
                    .oCSPEnabled(config.getOCSPEnabled())
                    .oCSPResponseCertificate(config.getOCSPResponderCertificate())
                    .oCSPResponderURI(config.getOCSPResponder());
        }
    }

    protected static class UserIdentityExtractorBuilder {

        private static final Function<X509Certificate[], X500Name> subject = certs -> {
            try {
                return new JcaX509CertificateHolder(certs[0]).getSubject();
            } catch (CertificateEncodingException e) {
                LOG.warn("Unable to get certificate Subject", e);
            }
            return null;
        };

        private static final Function<X509Certificate[], X500Name> issuer = certs -> {
            try {
                return new JcaX509CertificateHolder(certs[0]).getIssuer();
            } catch (CertificateEncodingException e) {
                LOG.warn("Unable to get certificate Issuer", e);
            }
            return null;
        };

        private static Function<X509Certificate[], String> getSerialnumberFunc(X509AuthenticatorConfigModel config) {
            return config.isSerialnumberHex() ?
                    certs -> Hex.toHexString(certs[0].getSerialNumber().toByteArray()) :
                    certs -> certs[0].getSerialNumber().toString();
        }

        private static Function<X509Certificate[], String> getIssuerDNFunc(X509AuthenticatorConfigModel config) {
            return config.isCanonicalDnEnabled() ?
                    certs -> certs[0].getIssuerX500Principal().getName(X500Principal.CANONICAL) :
                    certs -> certs[0].getIssuerDN().getName();
        }

        static UserIdentityExtractor fromConfig(X509AuthenticatorConfigModel config) {

            X509AuthenticatorConfigModel.MappingSourceType userIdentitySource = config.getMappingSourceType();
            String pattern = config.getRegularExpression();

            UserIdentityExtractor extractor = null;
            Function<X509Certificate[], String> func = null;
            switch (userIdentitySource) {

                case SUBJECTDN:
                    func = config.isCanonicalDnEnabled() ?
                            certs -> certs[0].getSubjectX500Principal().getName(X500Principal.CANONICAL) :
                            certs -> certs[0].getSubjectDN().getName();
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(pattern, func);
                    break;
                case ISSUERDN:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(pattern, getIssuerDNFunc(config));
                    break;
                case SERIALNUMBER:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(DEFAULT_MATCH_ALL_EXPRESSION, getSerialnumberFunc(config));
                    break;
                case SHA256_THUMBPRINT:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(DEFAULT_MATCH_ALL_EXPRESSION, certs -> {
                        try {
                            return Hex.toHexString(HashUtils.hash(JavaAlgorithm.SHA256, certs[0].getEncoded()));
                        } catch (CertificateEncodingException | HashException e) {
                            LOG.warn("Unable to get certificate's thumbprint", e);
                        }
                        return null;
                    });
                    break;
                case SERIALNUMBER_ISSUERDN:
                    func = certs -> getSerialnumberFunc(config).apply(certs) + Constants.CFG_DELIMITER + getIssuerDNFunc(config).apply(certs);
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(DEFAULT_MATCH_ALL_EXPRESSION, func);
                    break;
                case SUBJECTDN_CN:
                    extractor = UserIdentityExtractor.getX500NameExtractor(BCStyle.CN, subject);
                    break;
                case SUBJECTDN_EMAIL:
                    extractor = UserIdentityExtractor
                            .either(UserIdentityExtractor.getX500NameExtractor(BCStyle.EmailAddress, subject))
                            .or(UserIdentityExtractor.getX500NameExtractor(BCStyle.E, subject));
                    break;
                case SUBJECTALTNAME_EMAIL:
                    extractor = UserIdentityExtractor.getSubjectAltNameExtractor(1);
                    break;
                case SUBJECTALTNAME_OTHERNAME:
                    extractor = UserIdentityExtractor.getSubjectAltNameExtractor(0);
                    break;
                case CERTIFICATE_PEM:
                    extractor = UserIdentityExtractor.getCertificatePemIdentityExtractor(config);
                    break;
                default:
                    LOG.warn("[UserIdentityExtractorBuilder:fromConfig] Unknown or unsupported user identity source: \"%s\"", userIdentitySource.getName());
                    break;
            }
            return extractor;
        }
    }

    @Autowired
    private UserIdentityToModelMapper userIdentityToModelMapper;

    protected class UserIdentityToModelMapperBuilder {

        public UserIdentityToModelMapper fromConfig(X509AuthenticatorConfigModel config) {

            X509AuthenticatorConfigModel.IdentityMapperType mapperType = config.getUserIdentityMapperType();
            String attributeName = config.getCustomAttributeName();

            UserIdentityToModelMapper mapper = null;
            switch (mapperType) {
                case USER_ATTRIBUTE:
                    mapper = userIdentityToModelMapper.getUserIdentityToCustomAttributeMapper(attributeName);
                    break;
                case USERNAME_EMAIL:
                    mapper = userIdentityToModelMapper.getUsernameOrEmailMapper();
                    break;
                default:
                    LOG.warn("[UserIdentityToModelMapperBuilder:fromConfig] Unknown or unsupported user identity mapper: \"{}\"", mapperType.getName());
            }
            return mapper;
        }
    }
}
