package org.keycloak.config.providers;

import org.keycloak.transaction.JBossJtaTransactionManagerLookup;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TransactionManagerLookupConfiguration {
    @Bean
    public JBossJtaTransactionManagerLookup jBossJtaTransactionManagerLookup() {
        return new JBossJtaTransactionManagerLookup();
    }
}
