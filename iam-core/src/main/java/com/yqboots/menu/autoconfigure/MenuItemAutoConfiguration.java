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
package com.yqboots.menu.autoconfigure;

import com.yqboots.menu.context.MenuItemImportListener;
import com.yqboots.menu.core.MenuItemManagerImpl;
import com.yqboots.menu.core.MenuItemManager;
import com.yqboots.menu.core.repository.MenuItemRepository;
import com.yqboots.menu.security.access.MenuItemObjectIdentityRetrieval;
import com.yqboots.security.access.support.ObjectIdentityRetrieval;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * The auto configuration class for MenuItem.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Configuration
@EnableConfigurationProperties(MenuItemProperties.class)
@Import({MenuItemImportListener.class})
public class MenuItemAutoConfiguration {
    @Autowired
    private MenuItemRepository menuItemRepository;

    @Autowired
    private MenuItemProperties properties;

    /**
     * Gets the bean of MenuItemManager.
     *
     * @return bean of MenuItemManager
     */
    @Bean
    public MenuItemManager menuItemManager() {
        return new MenuItemManagerImpl(menuItemRepository, properties);
    }

    @Configuration
    @ConditionalOnClass(ObjectIdentityRetrieval.class)
    protected static class MenuItemSecurityConfiguration {
        @Bean
        public ObjectIdentityRetrieval menuItemObjectIdentityRetrieval() {
            return new MenuItemObjectIdentityRetrieval();
        }
    }

}
