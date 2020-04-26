package org.keycloak.config.providers;

import org.keycloak.timer.basic.BasicTimerProviderFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TimerConfiguration {
    @Bean
    public BasicTimerProviderFactory basicTimerProviderFactory() {
        return new BasicTimerProviderFactory();
    }
}
