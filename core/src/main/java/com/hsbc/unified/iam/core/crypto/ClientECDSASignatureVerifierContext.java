package com.hsbc.unified.iam.core.crypto;

import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.ClientModel;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

public class ClientECDSASignatureVerifierContext extends AsymmetricSignatureVerifierContext {
    private final ClientModel client;
    private final JWSInput input;
    @Autowired
    private PublicKeyStorageManager publicKeyStorageManager;

    public ClientECDSASignatureVerifierContext(ClientModel client, JWSInput input) {
        super();
        this.client = client;
        this.input = input;
    }

    @PostConstruct
    public void afterPropertiesSet() throws VerificationException {
        setKey(getKey(client, input));
    }

    private KeyWrapper getKey(ClientModel client, JWSInput input) throws VerificationException {
        KeyWrapper key = publicKeyStorageManager.getClientPublicKeyWrapper(client, input);
        if (key == null) {
            throw new VerificationException("Key not found");
        }
        return key;
    }

    @Override
    public boolean verify(byte[] data, byte[] signature) throws VerificationException {
        try {
            /*
            Fallback for backwards compatibility of ECDSA signed tokens which were issued in previous versions.
            TODO remove by https://issues.jboss.org/browse/KEYCLOAK-11911
             */
            int expectedSize = ECDSASignatureProvider.ECDSA.valueOf(getAlgorithm()).getSignatureLength();
            byte[] derSignature = expectedSize != signature.length && signature[0] == 0x30 ? signature : ECDSASignatureProvider.concatenatedRSToASN1DER(signature, expectedSize);
            return super.verify(data, derSignature);
        } catch (Exception e) {
            throw new VerificationException("Signing failed", e);
        }
    }
}
