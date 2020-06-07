package org.keycloak.config;

import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.authorization.AuthorizationSpi;
import org.keycloak.authorization.policy.provider.PolicySpi;
import org.keycloak.authorization.store.StoreFactorySpi;
import org.keycloak.broker.provider.IdentityProviderMapperSpi;
import org.keycloak.broker.provider.IdentityProviderSpi;
import org.keycloak.connections.httpclient.HttpClientSpi;
import org.keycloak.credential.CredentialSpi;
import org.keycloak.credential.hash.PasswordHashSpi;
import org.keycloak.email.EmailSenderSpi;
import org.keycloak.email.EmailTemplateSpi;
import org.keycloak.events.EventListenerSpi;
import org.keycloak.events.EventStoreSpi;
import org.keycloak.exportimport.ExportSpi;
import org.keycloak.exportimport.ImportSpi;
import org.keycloak.forms.login.LoginFormsSpi;
import org.keycloak.keys.KeySpi;
import org.keycloak.keys.PublicKeyStorageSpi;
import org.keycloak.locale.LocaleSelectorSPI;
import org.keycloak.locale.LocaleUpdaterSPI;
import org.keycloak.models.*;
import org.keycloak.models.dblock.DBLockSpi;
import org.keycloak.models.session.UserSessionPersisterSpi;
import org.keycloak.policy.PasswordPolicyManagerSpi;
import org.keycloak.policy.PasswordPolicySpi;
import org.keycloak.protocol.ClientInstallationSpi;
import org.keycloak.protocol.LoginProtocolSpi;
import org.keycloak.protocol.ProtocolMapperSpi;
import org.keycloak.protocol.oidc.TokenIntrospectionSpi;
import org.keycloak.protocol.oidc.ext.OIDCExtSPI;
import org.keycloak.provider.*;
import org.keycloak.scripting.ScriptingSpi;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.clientregistration.ClientRegistrationSpi;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicySpi;
import org.keycloak.services.managers.BruteForceProtectorSpi;
import org.keycloak.services.resource.RealmResourceSPI;
import org.keycloak.services.util.JsonConfigProviderFactory;
import org.keycloak.services.x509.X509ClientCertificateLookupSpi;
import org.keycloak.sessions.AuthenticationSessionSpi;
import org.keycloak.sessions.StickySessionEncoderSpi;
import org.keycloak.storage.UserStorageProviderSpi;
import org.keycloak.storage.client.ClientStorageProviderSpi;
import org.keycloak.storage.federated.UserFederatedStorageProviderSpi;
import org.keycloak.theme.DefaultThemeManagerFactory;
import org.keycloak.theme.ThemeResourceSpi;
import org.keycloak.theme.ThemeSelectorSpi;
import org.keycloak.theme.ThemeSpi;
import org.keycloak.timer.TimerSpi;
import org.keycloak.truststore.TruststoreSpi;
import org.keycloak.urls.HostnameSpi;
import org.keycloak.validation.ClientValidationSPI;
import org.keycloak.vault.VaultSpi;
import org.keycloak.wellknown.WellKnownSpi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@Configuration
public class KeycloakWebConfiguration {
    @Bean
    public ConfigProviderFactory configProviderFactory() {
        return new JsonConfigProviderFactory();
    }

    @Bean
    public KeycloakSessionFactory keycloakSessionFactory() {
        DefaultKeycloakSessionFactory factory = new DefaultKeycloakSessionFactory();
        factory.setThemeManagerFactory(keycloakThemeManagerFactory());
        factory.setProviderManager(keycloakProviderManager());
        factory.setSpis(keycloakSpis());
        factory.afterPropertiesSet();
        return factory;
    }

    private DefaultThemeManagerFactory keycloakThemeManagerFactory() {
        return new DefaultThemeManagerFactory();
    }

    @Bean
    public ProviderManager keycloakProviderManager() {
        ClassLoader baseClassLoader = getClass().getClassLoader();

        KeycloakDeploymentInfo info = KeycloakDeploymentInfo.create().services();
        ProviderManager result = new ProviderManager(info, baseClassLoader, Config.scope().getArray("providers"));

        List<ProviderLoader> loaders = new LinkedList<>();
        loaders.add(new DefaultProviderLoader(info, baseClassLoader));
        loaders.add(new DeploymentProviderLoader(info));
        result.setLoaders(loaders);

        return result;
    }

    @Bean(name = "keycloakSpis")
    public Set<Spi> keycloakSpis() {
        Set<Spi> results = new HashSet<>();
        results.add(new ActionTokenStoreSpi());
        results.add(new AuthenticationSessionSpi());
        results.add(new AuthenticatorSpi());
        results.add(new AuthorizationSpi());
        results.add(new BruteForceProtectorSpi());
        results.add(new ClientAuthenticatorSpi());
        results.add(new ClientInstallationSpi());
        results.add(new ClientRegistrationPolicySpi());
        results.add(new ClientRegistrationSpi());
        results.add(new ClientStorageProviderSpi());
        results.add(new ClientValidationSPI());
        results.add(new CodeToTokenStoreSpi());
        results.add(new CredentialSpi());
        results.add(new DBLockSpi());
        results.add(new EmailSenderSpi());
        results.add(new EmailTemplateSpi());
        results.add(new EventListenerSpi());
        results.add(new EventStoreSpi());
        results.add(new ExceptionConverterSpi());
        results.add(new ExportSpi());
        results.add(new FormActionSpi());
        results.add(new FormAuthenticatorSpi());
        results.add(new HostnameSpi());
        results.add(new HttpClientSpi());
        results.add(new IdentityProviderMapperSpi());
        results.add(new IdentityProviderSpi());
        results.add(new ImportSpi());
        results.add(new KeySpi());
        results.add(new LocaleSelectorSPI());
        results.add(new LocaleUpdaterSPI());
        results.add(new LoginFormsSpi());
        results.add(new LoginProtocolSpi());
        results.add(new OIDCExtSPI());
        results.add(new PasswordHashSpi());
        results.add(new PasswordPolicyManagerSpi());
        results.add(new PasswordPolicySpi());
        results.add(new PolicySpi());
        results.add(new ProtocolMapperSpi());
        results.add(new PublicKeyStorageSpi());
        results.add(new RealmResourceSPI());
        results.add(new RealmSpi());
        results.add(new RequiredActionSpi());
        results.add(new ScriptingSpi());
        results.add(new SingleUseTokenStoreSpi());
        results.add(new StickySessionEncoderSpi());
        results.add(new StoreFactorySpi());
        results.add(new ThemeResourceSpi());
        results.add(new ThemeSelectorSpi());
        results.add(new ThemeSpi());
        results.add(new TimerSpi());
        results.add(new TokenIntrospectionSpi());
        results.add(new TruststoreSpi());
        results.add(new UserFederatedStorageProviderSpi());
        results.add(new UserSessionPersisterSpi());
        results.add(new UserSessionSpi());
        results.add(new UserSpi());
        results.add(new UserStorageProviderSpi());
        results.add(new VaultSpi());
        results.add(new WellKnownSpi());
        results.add(new X509ClientCertificateLookupSpi());

        return results;
    }
}
