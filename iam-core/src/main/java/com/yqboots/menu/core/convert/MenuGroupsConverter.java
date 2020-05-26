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
package com.yqboots.menu.core.convert;

import com.yqboots.menu.core.MenuItem;
import org.springframework.core.convert.converter.Converter;

import java.util.*;

/**
 * Convert from list of MenuItem to Map, representing the hierarchy of menu group, menu item group and menu item.
 * <p>It makes 3 levels of menus, the developer should provide menuItemGroup field in MenuItem, as well as menuGroup.<p/>
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class MenuGroupsConverter implements Converter<List<MenuItem>, Map<String, Map<String, List<MenuItem>>>> {
    /**
     * Convert the source object of type {@code S} to target type {@code T}.
     *
     * @param source the source object to convert, which must be an instance of {@code S} (never {@code null})
     * @return the converted object, which must be an instance of {@code T} (potentially {@code null})
     * @throws IllegalArgumentException if the source cannot be converted to the desired target type
     */
    @Override
    public Map<String, Map<String, List<MenuItem>>> convert(final List<MenuItem> source) {
        final Map<String, Map<String, List<MenuItem>>> results = new LinkedHashMap<>();

        Map<String, List<MenuItem>> menuGroup;
        for (final MenuItem menuItem : source) {
            String menuGroupKey = menuItem.getMenuGroup();
            if (results.containsKey(menuGroupKey)) {
                menuGroup = results.get(menuGroupKey);
                if (menuGroup.containsKey(menuItem.getMenuItemGroup())) {
                    menuGroup.get(menuItem.getMenuItemGroup()).add(menuItem);
                } else {
                    List<MenuItem> items = new ArrayList<>();
                    items.add(menuItem);
                    menuGroup.put(menuItem.getMenuItemGroup(), items);
                }
            } else {
                menuGroup = new LinkedHashMap<>();

                List<MenuItem> items = new ArrayList<>();
                items.add(menuItem);
                menuGroup.put(menuItem.getMenuItemGroup(), items);

                results.put(menuItem.getMenuGroup(), menuGroup);
            }
        }

        return results;
    }
}
