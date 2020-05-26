/*
 * Copyright 2015-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yqboots.dict.core;

import org.hibernate.validator.constraints.Length;
import org.springframework.data.jpa.domain.AbstractPersistable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Index;
import javax.persistence.Table;
import javax.validation.constraints.NotEmpty;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * The DataDict domain class.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Entity
@Table(name = "PRJ_DATA_DICT", indexes = {
        @Index(name = "IDX_DICT_NAME", columnList = "name"),
        @Index(name = "IDX_DICT_NAME_VALUE", columnList = "name, value", unique = true)
})
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DataDict extends AbstractPersistable<Long> {
    @Column(length = 32, nullable = false)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 32)
    private String name;

    @Column(length = 64, nullable = false)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 64)
    private String text;

    @Column(length = 32, nullable = false)
    @XmlElement(required = true)
    @NotEmpty
    @Length(max = 32)
    private String value;

    @Column(length = 255)
    @Length(max = 255)
    private String description;

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

    public String getText() {
        return text;
    }

    public void setText(final String text) {
        this.text = text;
    }

    public String getValue() {
        return value;
    }

    public void setValue(final String value) {
        this.value = value;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }
}
