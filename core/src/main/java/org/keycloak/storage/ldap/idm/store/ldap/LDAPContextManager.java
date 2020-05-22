package org.keycloak.storage.ldap.idm.store.ldap;

import org.keycloak.models.LDAPConstants;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.vault.VaultCharSecret;
import org.keycloak.vault.VaultTranscriber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import java.io.IOException;
import java.nio.CharBuffer;
import java.util.*;

import static javax.naming.Context.SECURITY_CREDENTIALS;

/**
 * @author mhajas
 */
public final class LDAPContextManager implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(LDAPContextManager.class);

    private final LDAPConfig ldapConfig;
    private StartTlsResponse tlsResponse;

    private VaultCharSecret vaultCharSecret = new VaultCharSecret() {
        @Override
        public Optional<CharBuffer> get() {
            return Optional.empty();
        }

        @Override
        public Optional<char[]> getAsArray() {
            return Optional.empty();
        }

        @Override
        public void close() {

        }
    };

    private LdapContext ldapContext;

    public LDAPContextManager(LDAPConfig connectionProperties) {
        this.ldapConfig = connectionProperties;
    }

    public static LDAPContextManager create(LDAPConfig connectionProperties) {
        return new LDAPContextManager(connectionProperties);
    }

    public static StartTlsResponse startTLS(LdapContext ldapContext, String authType, String bindDN, char[] bindCredential) throws NamingException {
        StartTlsResponse tls = null;

        try {
            tls = (StartTlsResponse) ldapContext.extendedOperation(new StartTlsRequest());
            tls.negotiate();

            ldapContext.addToEnvironment(Context.SECURITY_AUTHENTICATION, authType);

            if (!LDAPConstants.AUTH_TYPE_NONE.equals(authType)) {
                ldapContext.addToEnvironment(Context.SECURITY_PRINCIPAL, bindDN);
                ldapContext.addToEnvironment(Context.SECURITY_CREDENTIALS, bindCredential);
            }
        } catch (Exception e) {
            LOG.error("Could not negotiate TLS", e);
            throw new AuthenticationException("Could not negotiate TLS");
        }

        // throws AuthenticationException when authentication fails
        ldapContext.lookup("");

        return tls;
    }

    /**
     * This method is used for admin connection and user authentication. Hence it returns just connection properties NOT related to
     * authentication (properties like bindType, bindDn, bindPassword). Caller of this method needs to fill auth-related connection properties
     * based on the fact whether he does admin connection or user authentication
     *
     * @param ldapConfig
     * @return
     */
    public static Hashtable<Object, Object> getNonAuthConnectionProperties(LDAPConfig ldapConfig) {
        HashMap<String, Object> env = new HashMap<>();

        env.put(Context.INITIAL_CONTEXT_FACTORY, ldapConfig.getFactoryName());

        String url = ldapConfig.getConnectionUrl();

        if (url != null) {
            env.put(Context.PROVIDER_URL, url);
        } else {
            LOG.warn("LDAP URL is null. LDAPOperationManager won't work correctly");
        }

        String useTruststoreSpi = ldapConfig.getUseTruststoreSpi();
        LDAPConstants.setTruststoreSpiIfNeeded(useTruststoreSpi, url, env);

        String connectionPooling = ldapConfig.getConnectionPooling();
        if (connectionPooling != null) {
            env.put("com.sun.jndi.ldap.connect.pool", connectionPooling);
        }

        String connectionTimeout = ldapConfig.getConnectionTimeout();
        if (connectionTimeout != null && !connectionTimeout.isEmpty()) {
            env.put("com.sun.jndi.ldap.connect.timeout", connectionTimeout);
        }

        String readTimeout = ldapConfig.getReadTimeout();
        if (readTimeout != null && !readTimeout.isEmpty()) {
            env.put("com.sun.jndi.ldap.read.timeout", readTimeout);
        }

        // Just dump the additional properties
        Properties additionalProperties = ldapConfig.getAdditionalConnectionProperties();
        if (additionalProperties != null) {
            for (Object key : additionalProperties.keySet()) {
                env.put(key.toString(), additionalProperties.getProperty(key.toString()));
            }
        }

        StringBuilder binaryAttrsBuilder = new StringBuilder();
        if (ldapConfig.isObjectGUID()) {
            binaryAttrsBuilder.append(LDAPConstants.OBJECT_GUID).append(" ");
        }
        if (ldapConfig.isEdirectory()) {
            binaryAttrsBuilder.append(LDAPConstants.NOVELL_EDIRECTORY_GUID).append(" ");
        }
        for (String attrName : ldapConfig.getBinaryAttributeNames()) {
            binaryAttrsBuilder.append(attrName).append(" ");
        }

        String binaryAttrs = binaryAttrsBuilder.toString().trim();
        if (!binaryAttrs.isEmpty()) {
            env.put("java.naming.ldap.attributes.binary", binaryAttrs);
        }

        return new Hashtable<>(env);
    }

    private void createLdapContext() throws NamingException {
        Hashtable<Object, Object> connProp = getConnectionProperties(ldapConfig);

        if (!LDAPConstants.AUTH_TYPE_NONE.equals(ldapConfig.getAuthType())) {
            vaultCharSecret = getVaultSecret();

            if (vaultCharSecret != null && !ldapConfig.isStartTls()) {
                connProp.put(SECURITY_CREDENTIALS, vaultCharSecret.getAsArray()
                        .orElse(ldapConfig.getBindCredential().toCharArray()));
            }
        }

        ldapContext = new InitialLdapContext(connProp, null);
        if (ldapConfig.isStartTls()) {
            tlsResponse = startTLS(ldapContext, ldapConfig.getAuthType(), ldapConfig.getBindDN(),
                    vaultCharSecret.getAsArray().orElse(ldapConfig.getBindCredential().toCharArray()));

            // Exception should be already thrown by LDAPContextManager.startTLS if "startTLS" could not be established, but rather do some additional check
            if (tlsResponse == null) {
                throw new NamingException("Wasn't able to establish LDAP connection through StartTLS");
            }
        }

    }

    public LdapContext getLdapContext() throws NamingException {
        if (ldapContext == null) createLdapContext();

        return ldapContext;
    }

    @Autowired
    private VaultTranscriber vaultTranscriber;

    private VaultCharSecret getVaultSecret() {
        return LDAPConstants.AUTH_TYPE_NONE.equals(ldapConfig.getAuthType())
                ? null
                : vaultTranscriber.getCharSecret(ldapConfig.getBindCredential());
    }

    // Get connection properties of admin connection
    private Hashtable<Object, Object> getConnectionProperties(LDAPConfig ldapConfig) {
        Hashtable<Object, Object> env = getNonAuthConnectionProperties(ldapConfig);

        if (!ldapConfig.isStartTls()) {
            String authType = ldapConfig.getAuthType();

            env.put(Context.SECURITY_AUTHENTICATION, authType);

            String bindDN = ldapConfig.getBindDN();

            char[] bindCredential = null;

            if (ldapConfig.getBindCredential() != null) {
                bindCredential = ldapConfig.getBindCredential().toCharArray();
            }

            if (!LDAPConstants.AUTH_TYPE_NONE.equals(authType)) {
                env.put(Context.SECURITY_PRINCIPAL, bindDN);
                env.put(Context.SECURITY_CREDENTIALS, bindCredential);
            }
        }

        if (LOG.isDebugEnabled()) {
            Map<Object, Object> copyEnv = new Hashtable<>(env);
            if (copyEnv.containsKey(Context.SECURITY_CREDENTIALS)) {
                copyEnv.put(Context.SECURITY_CREDENTIALS, "**************************************");
            }
            LOG.debug("Creating LdapContext using properties: [{}]", copyEnv);
        }

        return env;
    }

    @Override
    public void close() {
        if (vaultCharSecret != null) vaultCharSecret.close();
        if (tlsResponse != null) {
            try {
                tlsResponse.close();
            } catch (IOException e) {
                LOG.error("Could not close Ldap tlsResponse.", e);
            }
        }

        if (ldapContext != null) {
            try {
                ldapContext.close();
            } catch (NamingException e) {
                LOG.error("Could not close Ldap context.", e);
            }
        }
    }
}
