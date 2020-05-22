package org.keycloak.authentication;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.AuthenticationExecutionModel;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Map;

public class AuthenticationSelectionOption {

    private final AuthenticationExecutionModel authExec;
    private final CredentialTypeMetadata credentialTypeMetadata;

    @Autowired
    private Map<String, Authenticator> authenticators;

    public AuthenticationSelectionOption(AuthenticationExecutionModel authExec) {
        this.authExec = authExec;
        Authenticator authenticator = authenticators.get(authExec.getAuthenticator());
        if (authenticator instanceof CredentialValidator) {
            CredentialProvider credentialProvider = ((CredentialValidator) authenticator).getCredentialProvider();

            CredentialTypeMetadataContext ctx = CredentialTypeMetadataContext.builder().build();
            credentialTypeMetadata = credentialProvider.getCredentialTypeMetadata(ctx);
        } else {
            credentialTypeMetadata = null;
        }
    }


    public AuthenticationExecutionModel getAuthenticationExecution() {
        return authExec;
    }

    public String getAuthExecId() {
        return authExec.getId();
    }

    public String getDisplayName() {
        return credentialTypeMetadata == null ? authExec.getAuthenticator() + "-display-name" : credentialTypeMetadata.getDisplayName();
    }

    public String getHelpText() {
        return credentialTypeMetadata == null ? authExec.getAuthenticator() + "-help-text" : credentialTypeMetadata.getHelpText();
    }

    public String getIconCssClass() {
        // For now, we won't allow to retrieve "iconCssClass" from the AuthenticatorFactory. We will see in the future if we need
        // this capability for authenticator factories, which authenticators don't implement credentialProvider
        return credentialTypeMetadata == null ? CredentialTypeMetadata.DEFAULT_ICON_CSS_CLASS : credentialTypeMetadata.getIconCssClass();
    }


    @Override
    public String toString() {
        return " authSelection - " + authExec.getAuthenticator();
    }
}
