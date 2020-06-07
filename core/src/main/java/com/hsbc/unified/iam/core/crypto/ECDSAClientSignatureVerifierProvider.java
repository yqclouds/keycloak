package com.hsbc.unified.iam.core.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;

public class ECDSAClientSignatureVerifierProvider implements ClientSignatureVerifierProvider {
    private final String algorithm;

    public ECDSAClientSignatureVerifierProvider(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public SignatureVerifierContext verifier(ClientModel client, JWSInput input) throws VerificationException {
        return new ClientECDSASignatureVerifierContext(client, input);
    }
}
