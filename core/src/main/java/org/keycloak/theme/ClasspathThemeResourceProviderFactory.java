package org.keycloak.theme;

import org.keycloak.Config;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.Properties;

public class ClasspathThemeResourceProviderFactory implements ThemeResourceProviderFactory, ThemeResourceProvider {

    public static final String THEME_RESOURCES_TEMPLATES = "theme-resources/templates/";
    public static final String THEME_RESOURCES_RESOURCES = "theme-resources/resources/";
    public static final String THEME_RESOURCES_MESSAGES = "theme-resources/messages/";

    private final String id;
    private final ClassLoader classLoader;

    public ClasspathThemeResourceProviderFactory(String id, ClassLoader classLoader) {
        this.id = id;
        this.classLoader = classLoader;
    }

    @Override
    public ThemeResourceProvider create() {
        return this;
    }

    @Override
    public URL getTemplate(String name) throws IOException {
        return classLoader.getResource(THEME_RESOURCES_TEMPLATES + name);
    }

    @Override
    public InputStream getResourceAsStream(String path) throws IOException {
        return classLoader.getResourceAsStream(THEME_RESOURCES_RESOURCES + path);
    }

    @Override
    public Properties getMessages(String baseBundlename, Locale locale) throws IOException {
        Properties m = new Properties();
        InputStream in = classLoader.getResourceAsStream(THEME_RESOURCES_MESSAGES + baseBundlename + "_" + locale.toString() + ".properties");
        if (in != null) {
            Charset encoding = PropertiesUtil.detectEncoding(in);
            // detectEncoding closes the stream
            try (Reader reader = new InputStreamReader(
                    classLoader.getResourceAsStream(THEME_RESOURCES_MESSAGES + baseBundlename + "_" + locale.toString() + ".properties"), encoding)) {
                m.load(reader);
            }
        }
        return m;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit() {
    }

    @Override
    public void close() {
    }

}
