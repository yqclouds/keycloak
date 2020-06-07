package org.keycloak.crypto;

import com.hsbc.unified.iam.core.crypto.ECDSASignatureProvider;

public class ServerECDSASignatureSignerContext extends AsymmetricSignatureSignerContext {
    private ServerAsymmetricSignatureSignerContext serverAsymmetricSignatureSignerContext;
    private String algorithm;

    public ServerECDSASignatureSignerContext(String algorithm) throws SignatureException {
        super(null);
        this.algorithm = algorithm;
    }

    @Override
    public void setKey(KeyWrapper key) {
        super.setKey(serverAsymmetricSignatureSignerContext.getKey(algorithm));
    }

    public ServerECDSASignatureSignerContext(KeyWrapper key) {
        super(key);
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            int size = ECDSASignatureProvider.ECDSA.valueOf(getAlgorithm()).getSignatureLength();
            return ECDSASignatureProvider.asn1derToConcatenatedRS(super.sign(data), size);
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }
}
