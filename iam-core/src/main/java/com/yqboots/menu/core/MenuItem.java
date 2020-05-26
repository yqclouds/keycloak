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

import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.data.jpa.domain.AbstractPersistable;

import javax.persistence.*;
import javax.validation.constraints.Max;
import javax.xml.bind.annotation.*;

/**
 * The MenuItem domain class.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Entity
@Table(name = "PRJ_MENUITEM", indexes = {
        @Index(name = "IDX_MENU_NAME", columnList = "name", unique = true)
})
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class MenuItem extends AbstractPersistable<Long> {
    @Column(nullable = false, length = 32, unique = true)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 32)
    private String name;

    @Column(nullable = false, length = 64)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 64)
    private String url;

    @Column(nullable = false, length = 32)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 32)
    private String menuGroup;

    @Column(length = 32)
    @Length(max = 32)
    private String menuItemGroup;

    @Max(value = 100)
    private Integer sequentialOrder = 0;

    /**
     * Sets the id of the entity.
     *
     * @param id the id to set
     */
    @Override
    public void setId(final Long id) {
        super.setId(id);
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(final String url) {
        this.url = url;
    }

    public String getMenuGroup() {
        return menuGroup;
    }

    public void setMenuGroup(final String menuGroup) {
        this.menuGroup = menuGroup;
    }

    public String getMenuItemGroup() {
        return menuItemGroup;
    }

    public void setMenuItemGroup(final String menuItemGroup) {
        this.menuItemGroup = menuItemGroup;
    }

    public Integer getSequentialOrder() {
        return sequentialOrder;
    }

    public void setSequentialOrder(final Integer sequentialOrder) {
        this.sequentialOrder = sequentialOrder;
    }
}
