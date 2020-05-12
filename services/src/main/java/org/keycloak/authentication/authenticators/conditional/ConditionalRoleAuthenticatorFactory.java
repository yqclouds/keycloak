package org.keycloak.authentication.authenticators.conditional;

import com.hsbc.unified.iam.core.entity.AuthenticationExecutionRequirement;
import org.keycloak.authentication.Authenticator;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component("ConditionalRoleAuthenticatorFactory")
@ProviderFactory(id = "conditional-user-role", providerClasses = Authenticator.class)
public class ConditionalRoleAuthenticatorFactory implements ConditionalAuthenticatorFactory {
    public static final String PROVIDER_ID = "conditional-user-role";
    protected static final String CONDITIONAL_USER_ROLE = "condUserRole";
    private static final AuthenticationExecutionRequirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionRequirement.REQUIRED, AuthenticationExecutionRequirement.DISABLED
    };
    private static List<ProviderConfigProperty> commonConfig;

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
                .property().name(CONDITIONAL_USER_ROLE).label("User role").helpText("Role the user should have to execute this flow").type(ProviderConfigProperty.STRING_TYPE).add()
                .build()
        );
    }

    @Override
    @Deprecated
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - user role";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
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
        return "Flow is executed only if user has the given role.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalRoleAuthenticator.SINGLETON;
    }
}
