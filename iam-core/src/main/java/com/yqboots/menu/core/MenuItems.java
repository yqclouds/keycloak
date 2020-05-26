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
package com.yqboots.menu.core;

import javax.xml.bind.annotation.*;
import java.io.Serializable;
import java.util.List;

/**
 * It defines the XML root element, which contains a list of MenuItem.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class MenuItems implements Serializable {
    @XmlElement(name = "menuItem", required = true)
    private List<MenuItem> menuItems;

    protected MenuItems() {
        super();
    }

    public MenuItems(final List<MenuItem> menuItems) {
        this();
        this.menuItems = menuItems;
    }

    public List<MenuItem> getMenuItems() {
        return menuItems;
    }

    public void setMenuItems(final List<MenuItem> menuItems) {
        this.menuItems = menuItems;
    }
}
