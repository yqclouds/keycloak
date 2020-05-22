/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.crypto;

import org.keycloak.stereotype.ProviderFactory;
import org.springframework.stereotype.Component;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("SHA384HashProviderFactory")
@ProviderFactory(id = JavaAlgorithm.SHA384, providerClasses = HashProvider.class)
public class SHA384HashProviderFactory implements HashProviderFactory {

    public static final String ID = JavaAlgorithm.SHA384;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public HashProvider create() {
        return new JavaAlgorithmHashProvider(ID);
    }
}
