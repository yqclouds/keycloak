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

package org.keycloak.theme;

import org.keycloak.models.KeycloakSession;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.File;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("FolderThemeProviderFactory")
@ProviderFactory(id = "folder", providerClasses = ThemeProvider.class)
public class FolderThemeProviderFactory implements ThemeProviderFactory {

    private FolderThemeProvider themeProvider;

    @Value("${dir}")
    private String dir;

    @Override
    public ThemeProvider create(KeycloakSession sessions) {
        return themeProvider;
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        File rootDir = null;
        if (dir != null) {
            rootDir = new File(dir);
        }
        themeProvider = new FolderThemeProvider(rootDir);
    }

    @Override
    public String getId() {
        return "folder";
    }

}
