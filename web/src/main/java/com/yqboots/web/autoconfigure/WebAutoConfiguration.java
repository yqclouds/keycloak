/*
 *
 *  * Copyright 2015-2016 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.yqboots.web.autoconfigure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.servlet.WebMvcProperties;
import org.springframework.boot.devtools.remote.client.HttpHeaderInterceptor;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.support.ErrorPageFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.InterceptingClientHttpRequestFactory;
import org.springframework.util.Base64Utils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import javax.servlet.DispatcherType;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.TimeZone;

/**
 * The configuration class for web module.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Configuration
@ConditionalOnWebApplication
public class WebAutoConfiguration implements WebMvcConfigurer {
    @Autowired
    private final WebMvcProperties mvcProperties = new WebMvcProperties();

    /**
     * {@inheritDoc}
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LocaleChangeInterceptor());
    }

    @Bean
    public LocaleResolver localeResolver() {
        final SessionLocaleResolver bean = new SessionLocaleResolver();
        bean.setDefaultLocale(mvcProperties.getLocale());
        bean.setDefaultTimeZone(TimeZone.getDefault());

        return bean;
    }

    @Bean
    public FilterRegistrationBean<ErrorPageFilter> errorPageFilter() {
        FilterRegistrationBean<ErrorPageFilter> registration = new FilterRegistrationBean<>();
        ErrorPageFilter errorPageFilter = new ErrorPageFilter();
        errorPageFilter.addErrorPages(new ErrorPage(MultipartException.class, "/error"));
        registration.setFilter(errorPageFilter);
        registration.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
        return registration;
    }

    @Bean
    public RestTemplate restTemplate() throws UnsupportedEncodingException {
        return new RestTemplate(clientHttpRequestFactory());
    }

    /**
     * TODO: Temporarily solution, waiting for upgrading to spring framework 4.3.1 or upper (new spring platform).
     *
     * @return ClientHttpRequestFactory
     */
    private ClientHttpRequestFactory clientHttpRequestFactory() {
        // embedded user/password, for RestTemplate
        final String token = Base64Utils.encodeToString(("user:password").getBytes(StandardCharsets.UTF_8));

        final List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        interceptors.add(new HttpHeaderInterceptor("Authorization", "Basic " + token));

        return new InterceptingClientHttpRequestFactory(new HttpComponentsClientHttpRequestFactory(), interceptors);
    }
}
