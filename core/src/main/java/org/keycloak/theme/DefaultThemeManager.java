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

import org.keycloak.Config;
import org.keycloak.common.Version;
import com.hsbc.unified.iam.core.util.StringPropertyReplacer;
import com.hsbc.unified.iam.core.util.SystemEnvProperties;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ThemeManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultThemeManager implements ThemeManager {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultThemeManager.class);

    private final DefaultThemeManagerFactory factory;
    private final KeycloakSession session;
    private List<ThemeProvider> providers;
    private String defaultTheme;

    public DefaultThemeManager(DefaultThemeManagerFactory factory, KeycloakSession session) {
        this.factory = factory;
        this.session = session;
        this.defaultTheme = Config.scope("theme").get("default", Version.NAME.toLowerCase());
    }

    private static Locale getParent(Locale locale) {
        if (Locale.ENGLISH.equals(locale)) {
            return null;
        }

        if (locale.getVariant() != null && !locale.getVariant().isEmpty()) {
            return new Locale(locale.getLanguage(), locale.getCountry());
        }

        if (locale.getCountry() != null && !locale.getCountry().isEmpty()) {
            return new Locale(locale.getLanguage());
        }

        return Locale.ENGLISH;
    }

    @Autowired
    private ThemeSelectorProvider themeSelectorProvider;

    @Override
    public Theme getTheme(Theme.Type type) {
        String name = themeSelectorProvider.getThemeName(type);
        return getTheme(name, type);
    }

    @Override
    public Theme getTheme(String name, Theme.Type type) {
        if (name == null) {
            name = defaultTheme;
        }

        Theme theme = factory.getCachedTheme(name, type);
        if (theme == null) {
            theme = loadTheme(name, type);
            if (theme == null) {
                theme = loadTheme("keycloak", type);
                if (theme == null) {
                    theme = loadTheme("base", type);
                }
                LOG.error("Failed to find {} theme {}, using built-in themes", type, name);
            } else {
                theme = factory.addCachedTheme(name, type, theme);
            }
        }
        return theme;
    }

    @Override
    public Set<String> nameSet(Theme.Type type) {
        Set<String> themes = new HashSet<String>();
        for (ThemeProvider p : getProviders()) {
            themes.addAll(p.nameSet(type));
        }
        return themes;
    }

    @Override
    public void clearCache() {
        factory.clearCache();
    }

    private Theme loadTheme(String name, Theme.Type type) {
        Theme theme = findTheme(name, type);
        List<Theme> themes = new LinkedList<>();
        themes.add(theme);

        if (theme.getImportName() != null) {
            String[] s = theme.getImportName().split("/");
            themes.add(findTheme(s[1], Theme.Type.valueOf(s[0].toUpperCase())));
        }

        if (theme.getParentName() != null) {
            for (String parentName = theme.getParentName(); parentName != null; parentName = theme.getParentName()) {
                theme = findTheme(parentName, type);
                themes.add(theme);

                if (theme.getImportName() != null) {
                    String[] s = theme.getImportName().split("/");
                    themes.add(findTheme(s[1], Theme.Type.valueOf(s[0].toUpperCase())));
                }
            }
        }

        return new ExtendingTheme(themes, session.getAllProviders(ThemeResourceProvider.class));
    }

    private Theme findTheme(String name, Theme.Type type) {
        for (ThemeProvider p : getProviders()) {
            if (p.hasTheme(name, type)) {
                try {
                    return p.getTheme(name, type);
                } catch (IOException e) {
                    LOG.error(p.getClass() + " failed to load theme, type={}, name={}", type, name);
                }
            }
        }
        return null;
    }

    private List<ThemeProvider> getProviders() {
        if (providers == null) {
            providers = new LinkedList(session.getAllProviders(ThemeProvider.class));
            Collections.sort(providers, (o1, o2) -> o2.getProviderPriority() - o1.getProviderPriority());
        }

        return providers;
    }

    private static class ExtendingTheme implements Theme {

        private List<Theme> themes;
        private Set<ThemeResourceProvider> themeResourceProviders;

        private Properties properties;

        private ConcurrentHashMap<String, ConcurrentHashMap<Locale, Properties>> messages = new ConcurrentHashMap<>();

        public ExtendingTheme(List<Theme> themes, Set<ThemeResourceProvider> themeResourceProviders) {
            this.themes = themes;
            this.themeResourceProviders = themeResourceProviders;
        }

        @Override
        public String getName() {
            return themes.get(0).getName();
        }

        @Override
        public String getParentName() {
            return themes.get(0).getParentName();
        }

        @Override
        public String getImportName() {
            return themes.get(0).getImportName();
        }

        @Override
        public Type getType() {
            return themes.get(0).getType();
        }

        @Override
        public URL getTemplate(String name) throws IOException {
            for (Theme t : themes) {
                URL template = t.getTemplate(name);
                if (template != null) {
                    return template;
                }
            }

            for (ThemeResourceProvider t : themeResourceProviders) {
                URL template = t.getTemplate(name);
                if (template != null) {
                    return template;
                }
            }

            return null;
        }

        @Override
        public InputStream getResourceAsStream(String path) throws IOException {
            for (Theme t : themes) {
                InputStream resource = t.getResourceAsStream(path);
                if (resource != null) {
                    return resource;
                }
            }

            for (ThemeResourceProvider t : themeResourceProviders) {
                InputStream resource = t.getResourceAsStream(path);
                if (resource != null) {
                    return resource;
                }
            }

            return null;
        }

        @Override
        public Properties getMessages(Locale locale) throws IOException {
            return getMessages("messages", locale);
        }

        @Override
        public Properties getMessages(String baseBundlename, Locale locale) throws IOException {
            if (messages.get(baseBundlename) == null || messages.get(baseBundlename).get(locale) == null) {
                Properties messages = new Properties();

                Locale parent = getParent(locale);

                if (parent != null) {
                    messages.putAll(getMessages(baseBundlename, parent));
                }

                for (ThemeResourceProvider t : themeResourceProviders) {
                    messages.putAll(t.getMessages(baseBundlename, locale));
                }

                ListIterator<Theme> itr = themes.listIterator(themes.size());
                while (itr.hasPrevious()) {
                    Properties m = itr.previous().getMessages(baseBundlename, locale);
                    if (m != null) {
                        messages.putAll(m);
                    }
                }

                this.messages.putIfAbsent(baseBundlename, new ConcurrentHashMap<Locale, Properties>());
                this.messages.get(baseBundlename).putIfAbsent(locale, messages);

                return messages;
            } else {
                return messages.get(baseBundlename).get(locale);
            }
        }

        @Override
        public Properties getProperties() throws IOException {
            if (properties == null) {
                Properties properties = new Properties();
                ListIterator<Theme> itr = themes.listIterator(themes.size());
                while (itr.hasPrevious()) {
                    Properties p = itr.previous().getProperties();
                    if (p != null) {
                        properties.putAll(p);
                    }
                }
                substituteProperties(properties);
                this.properties = properties;
                return properties;
            } else {
                return properties;
            }
        }

        /**
         * Iterate over all string properties defined in "theme.properties" then substitute the value with system property or environment variables.
         * See {@link StringPropertyReplacer#replaceProperties} for details about the different formats.
         */
        private void substituteProperties(final Properties properties) {
            for (final String propertyName : properties.stringPropertyNames()) {
                properties.setProperty(propertyName, StringPropertyReplacer.replaceProperties(properties.getProperty(propertyName), new SystemEnvProperties()));
            }
        }
    }

}