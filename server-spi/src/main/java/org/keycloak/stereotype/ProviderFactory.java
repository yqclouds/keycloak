package org.keycloak.stereotype;

import org.keycloak.provider.Provider;
import org.springframework.stereotype.Component;

import java.lang.annotation.*;

/**
 * @author Eric H B Zhan
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Component
public @interface ProviderFactory {
    String id() default "";

    Class<? extends Provider>[] providerClasses();
}
