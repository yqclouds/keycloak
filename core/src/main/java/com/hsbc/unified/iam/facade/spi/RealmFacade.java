package com.hsbc.unified.iam.facade.spi;

import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.List;

public interface RealmFacade {
    RealmModel createRealm(RealmRepresentation request);

    List<RealmRepresentation> getRealms();
}
