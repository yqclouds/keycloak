package org.keycloak.authentication.authenticators.conditional;

import com.hsbc.unified.iam.core.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.Authenticator;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.List;

@Component("ConditionalUserConfiguredAuthenticatorFactory")
@ProviderFactory(id = "conditional-user-configured", providerClasses = Authenticator.class)
public class ConditionalUserConfiguredAuthenticatorFactory implements ConditionalAuthenticatorFactory {
    public static final String PROVIDER_ID = "conditional-user-configured";
    protected static final String CONDITIONAL_USER_ROLE = "condUserConfigured";
    private static final AuthenticationExecutionRequirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionRequirement.REQUIRED, AuthenticationExecutionRequirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - user configured";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
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
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Executes the current flow only if authenticators are configured";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalUserConfiguredAuthenticator.SINGLETON;
    }
}
