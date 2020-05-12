package org.keycloak.authentication.authenticators.client;

import com.hsbc.unified.iam.core.entity.AuthenticationExecutionRequirement;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.models.ClientModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Component("X509ClientAuthenticator")
@ProviderFactory(id = "client-x509", providerClasses = ClientAuthenticator.class)
public class X509ClientAuthenticator extends AbstractClientAuthenticator {
    private static final Logger LOG = LoggerFactory.getLogger(X509ClientAuthenticator.class);

    public static final String PROVIDER_ID = "client-x509";
    public static final String ATTR_PREFIX = "x509";
    public static final String ATTR_SUBJECT_DN = ATTR_PREFIX + ".subjectdn";

//    protected static ServicesLogger LOG = ServicesLogger.LOGGER;

    @Autowired(required = false)
    private X509ClientCertificateLookup x509ClientCertificateLookup;

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        if (x509ClientCertificateLookup == null) {
            LOG.error("\"{}\" Spi is not available, did you forget to update the configuration?",
                    X509ClientCertificateLookup.class.getName());
            return;
        }

        X509Certificate[] certs = null;
        ClientModel client = null;
        try {
            certs = x509ClientCertificateLookup.getCertificateChain(context.getHttpRequest());
            String client_id = null;
            MediaType mediaType = context.getHttpRequest().getHttpHeaders().getMediaType();
            boolean hasFormData = mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

            MultivaluedMap<String, String> formData = hasFormData ? context.getHttpRequest().getDecodedFormParameters() : null;
            MultivaluedMap<String, String> queryParams = context.getHttpRequest().getUri().getQueryParameters();

            if (formData != null) {
                client_id = formData.getFirst(OAuth2Constants.CLIENT_ID);
            }

            if (client_id == null && queryParams != null) {
                client_id = queryParams.getFirst(OAuth2Constants.CLIENT_ID);
            }

            if (client_id == null) {
                client_id = context.getSession().getAttribute("client_id", String.class);
            }

            if (client_id == null) {
                Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Missing client_id parameter");
                context.challenge(challengeResponse);
                return;
            }

            client = context.getRealm().getClientByClientId(client_id);
            if (client == null) {
                context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
                return;
            }
            context.getEvent().client(client_id);
            context.setClient(client);

            if (!client.isEnabled()) {
                context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
                return;
            }
        } catch (GeneralSecurityException e) {
            LOG.error("[X509ClientCertificateAuthenticator:authenticate] Exception: {}", e.getMessage());
            context.attempted();
            return;
        }

        if (certs == null || certs.length == 0) {
            // No x509 client cert, fall through and
            // continue processing the rest of the authentication flow
            LOG.debug("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
            context.attempted();
            return;
        }

        String subjectDNRegexp = client.getAttribute(ATTR_SUBJECT_DN);
        if (subjectDNRegexp == null || subjectDNRegexp.length() == 0) {
            LOG.error("[X509ClientCertificateAuthenticator:authenticate] " + ATTR_SUBJECT_DN + " is null or empty");
            context.attempted();
            return;
        }
        Pattern subjectDNPattern = Pattern.compile(subjectDNRegexp);

        Optional<String> matchedCertificate = Arrays.stream(certs)
                .map(certificate -> certificate.getSubjectDN().getName())
                .filter(subjectdn -> subjectDNPattern.matcher(subjectdn).matches())
                .findFirst();

        if (!matchedCertificate.isPresent()) {
            // We do quite expensive operation here, so better check the logging level beforehand.
            if (LOG.isDebugEnabled()) {
                LOG.debug("[X509ClientCertificateAuthenticator:authenticate] Couldn't match any certificate for pattern " + subjectDNRegexp);
                LOG.debug("[X509ClientCertificateAuthenticator:authenticate] Available SubjectDNs: " +
                        Arrays.stream(certs)
                                .map(cert -> cert.getSubjectDN().getName())
                                .collect(Collectors.toList()));
            }
            context.attempted();
            return;
        } else {
            LOG.debug("[X509ClientCertificateAuthenticator:authenticate] Matched " + matchedCertificate.get() + " certificate.");
        }

        context.success();
    }

    public String getDisplayType() {
        return "X509 Certificate";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionRequirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return Collections.emptyList();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        return Collections.emptyMap();
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add(OIDCLoginProtocol.TLS_CLIENT_AUTH);
            return results;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public String getHelpText() {
        return "Validates client based on a X509 Certificate";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
