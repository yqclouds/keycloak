package org.keycloak.models.credential.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import org.keycloak.common.util.Base64;

import java.io.IOException;

public class PasswordSecretData {

    public static final Logger LOG = LoggerFactory.getLogger(PasswordSecretData.class);

    private final String value;
    private final byte[] salt;

    @JsonCreator
    public PasswordSecretData(@JsonProperty("value") String value, @JsonProperty("salt") String salt) throws IOException {
        if (salt == null || "__SALT__".equals(salt)) {
            this.value = value;
            this.salt = null;
        } else {
            this.value = value;
            this.salt = Base64.decode(salt);
        }
    }

    public PasswordSecretData(String value, byte[] salt) {
        this.value = value;
        this.salt = salt;
    }

    public String getValue() {
        return value;
    }

    public byte[] getSalt() {
        return salt;
    }
}
