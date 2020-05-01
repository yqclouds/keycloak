package org.keycloak.stereotype;

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
}
