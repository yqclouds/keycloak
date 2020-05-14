/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hsbc.unified.iam.entity;

import org.hibernate.annotations.Nationalized;

import javax.persistence.*;
import java.io.Serializable;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@NamedQueries({
        @NamedQuery(name = "deleteRealmAttributesByRealm", query = "delete from RealmAttribute attr where attr.realm = :realm")
})
@Table(name = "REALM_ATTRIBUTE")
@Entity
@IdClass(RealmAttribute.Key.class)
public class RealmAttribute implements Serializable {
    public static final String DISPLAY_NAME = "displayName";
    public static final String DISPLAY_NAME_HTML = "displayNameHtml";

    public static final String ACTION_TOKEN_GENERATED_BY_ADMIN_LIFESPAN = "actionTokenGeneratedByAdminLifespan";
    public static final String ACTION_TOKEN_GENERATED_BY_USER_LIFESPAN = "actionTokenGeneratedByUserLifespan";

    // KEYCLOAK-7688 Offline Session Max for Offline Token
    public static final String OFFLINE_SESSION_MAX_LIFESPAN_ENABLED = "offlineSessionMaxLifespanEnabled";
    public static final String OFFLINE_SESSION_MAX_LIFESPAN = "offlineSessionMaxLifespan";

    public static final String WEBAUTHN_POLICY_RP_ENTITY_NAME = "webAuthnPolicyRpEntityName";
    public static final String WEBAUTHN_POLICY_SIGNATURE_ALGORITHMS = "webAuthnPolicySignatureAlgorithms";
    public static final String WEBAUTHN_POLICY_RP_ID = "webAuthnPolicyRpId";
    public static final String WEBAUTHN_POLICY_ATTESTATION_CONVEYANCE_PREFERENCE = "webAuthnPolicyAttestationConveyancePreference";
    public static final String WEBAUTHN_POLICY_AUTHENTICATOR_ATTACHMENT = "webAuthnPolicyAuthenticatorAttachment";
    public static final String WEBAUTHN_POLICY_REQUIRE_RESIDENT_KEY = "webAuthnPolicyRequireResidentKey";
    public static final String WEBAUTHN_POLICY_USER_VERIFICATION_REQUIREMENT = "webAuthnPolicyUserVerificationRequirement";
    public static final String WEBAUTHN_POLICY_CREATE_TIMEOUT = "webAuthnPolicyCreateTimeout";
    public static final String WEBAUTHN_POLICY_AVOID_SAME_AUTHENTICATOR_REGISTER = "webAuthnPolicyAvoidSameAuthenticatorRegister";
    public static final String WEBAUTHN_POLICY_ACCEPTABLE_AAGUIDS = "webAuthnPolicyAcceptableAaguids";

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;

    @Id
    @Column(name = "NAME")
    protected String name;
    @Nationalized
    @Column(name = "VALUE")
    protected String value;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof RealmAttribute)) return false;

        RealmAttribute key = (RealmAttribute) o;

        if (name != null ? !name.equals(key.name) : key.name != null) return false;
        if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = realm != null ? realm.getId().hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    public static class Key implements Serializable {

        protected Realm realm;

        protected String name;

        public Key() {
        }

        public Key(Realm user, String name) {
            this.realm = user;
            this.name = name;
        }

        public Realm getRealm() {
            return realm;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            Key key = (Key) o;

            if (name != null ? !name.equals(key.name) : key.name != null) return false;
            if (realm != null ? !realm.getId().equals(key.realm != null ? key.realm.getId() : null) : key.realm != null)
                return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = realm != null ? realm.getId().hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            return result;
        }
    }


}
