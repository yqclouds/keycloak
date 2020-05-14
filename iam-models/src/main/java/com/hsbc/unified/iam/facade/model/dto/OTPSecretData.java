package com.hsbc.unified.iam.facade.model.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class OTPSecretData {
    private final String value;

    @JsonCreator
    public OTPSecretData(@JsonProperty("value") String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
