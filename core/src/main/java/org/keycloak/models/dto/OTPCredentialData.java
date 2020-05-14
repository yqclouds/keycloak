package org.keycloak.models.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class OTPCredentialData {
    private final String subType;
    private final int digits;
    private final int period;
    private final String algorithm;
    private int counter;

    @JsonCreator
    public OTPCredentialData(@JsonProperty("subType") String subType,
                             @JsonProperty("digits") int digits,
                             @JsonProperty("counter") int counter,
                             @JsonProperty("period") int period,
                             @JsonProperty("algorithm") String algorithm) {
        this.subType = subType;
        this.digits = digits;
        this.counter = counter;
        this.period = period;
        this.algorithm = algorithm;
    }

    public String getSubType() {
        return subType;
    }

    public int getDigits() {
        return digits;
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

    public int getPeriod() {
        return period;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
