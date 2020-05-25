package com.hsbc.unified.iam.web.convert.converter;

import org.keycloak.representations.idm.ClientRepresentation;
import org.springframework.core.convert.converter.Converter;

/**
 * Provider plugin interface for importing clients from an arbitrary configuration format
 */
public interface ClientDescriptionConverter extends Converter<String, ClientRepresentation> {
    boolean supports(String description);
}
