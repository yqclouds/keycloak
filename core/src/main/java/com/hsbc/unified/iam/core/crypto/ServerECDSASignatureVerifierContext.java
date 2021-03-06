package com.hsbc.unified.iam.core.crypto;

import org.keycloak.common.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;

public class ServerECDSASignatureVerifierContext extends AsymmetricSignatureVerifierContext {
    private final String kid;
    private final String algorithm;

    public ServerECDSASignatureVerifierContext(String kid, String algorithm) throws VerificationException {
        super();

        this.kid = kid;
        this.algorithm = algorithm;
    }

    @Autowired
    private ServerAsymmetricSignatureVerifierContext serverAsymmetricSignatureVerifierContext;

    @PostConstruct
    public void afterPropertiesSet() throws VerificationException {
        setKey(serverAsymmetricSignatureVerifierContext.getKey(kid, algorithm));
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
