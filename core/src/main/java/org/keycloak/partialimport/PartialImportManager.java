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

package org.keycloak.partialimport;

import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.PartialImportRepresentation;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;

/**
 * This class manages the PartialImport handlers.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class PartialImportManager {
    private final List<PartialImport> partialImports = new ArrayList<>();

    private final PartialImportRepresentation rep;
    private final RealmModel realm;

    public PartialImportManager(PartialImportRepresentation rep, RealmModel realm) {
        this.rep = rep;
        this.realm = realm;
        // Do not change the order of these!!!
        partialImports.add(new ClientsPartialImport());
        partialImports.add(new RolesPartialImport());
        partialImports.add(new IdentityProvidersPartialImport());
        partialImports.add(new GroupsPartialImport());
        partialImports.add(new UsersPartialImport());
    }

    public Response saveResources() {

        PartialImportResults results = new PartialImportResults();

        for (PartialImport partialImport : partialImports) {
            try {
                partialImport.prepare(rep, realm);
            } catch (ErrorResponseException error) {
                return error.getResponse();
            }
        }

        for (PartialImport partialImport : partialImports) {
            try {
                partialImport.removeOverwrites(realm);
                results.addAllResults(partialImport.doImport(rep, realm));
            } catch (ErrorResponseException error) {
                return error.getResponse();
            }
        }

        return Response.ok(results).build();
    }
}
