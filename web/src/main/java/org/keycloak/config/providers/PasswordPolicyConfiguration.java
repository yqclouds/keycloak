package org.keycloak.config.providers;

import org.keycloak.policy.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PasswordPolicyConfiguration {
    @Bean
    public DigitsPasswordPolicyProviderFactory digitsPasswordPolicyProviderFactory() {
        return new DigitsPasswordPolicyProviderFactory();
    }

    @Bean
    public BlacklistPasswordPolicyProviderFactory blacklistPasswordPolicyProviderFactory() {
        return new BlacklistPasswordPolicyProviderFactory();
    }

    @Bean
    public LowerCasePasswordPolicyProviderFactory lowerCasePasswordPolicyProviderFactory() {
        return new LowerCasePasswordPolicyProviderFactory();
    }

    @Bean
    public HashAlgorithmPasswordPolicyProviderFactory hashAlgorithmPasswordPolicyProviderFactory() {
        return new HashAlgorithmPasswordPolicyProviderFactory();
    }

    @Bean
    public ForceExpiredPasswordPolicyProviderFactory forceExpiredPasswordPolicyProviderFactory() {
        return new ForceExpiredPasswordPolicyProviderFactory();
    }

    @Bean
    public HashIterationsPasswordPolicyProviderFactory hashIterationsPasswordPolicyProviderFactory() {
        return new HashIterationsPasswordPolicyProviderFactory();
    }

    @Bean
    public NotUsernamePasswordPolicyProviderFactory notUsernamePasswordPolicyProviderFactory() {
        return new NotUsernamePasswordPolicyProviderFactory();
    }

    @Bean
    public LengthPasswordPolicyProviderFactory lengthPasswordPolicyProviderFactory() {
        return new LengthPasswordPolicyProviderFactory();
    }

    @Bean
    public HistoryPasswordPolicyProviderFactory historyPasswordPolicyProviderFactory() {
        return new HistoryPasswordPolicyProviderFactory();
    }

    @Bean
    public UpperCasePasswordPolicyProviderFactory upperCasePasswordPolicyProviderFactory() {
        return new UpperCasePasswordPolicyProviderFactory();
    }

    @Bean
    public SpecialCharsPasswordPolicyProviderFactory specialCharsPasswordPolicyProviderFactory() {
        return new SpecialCharsPasswordPolicyProviderFactory();
    }

    @Bean
    public RegexPatternsPasswordPolicyProviderFactory regexPatternsPasswordPolicyProviderFactory() {
        return new RegexPatternsPasswordPolicyProviderFactory();
    }
}
