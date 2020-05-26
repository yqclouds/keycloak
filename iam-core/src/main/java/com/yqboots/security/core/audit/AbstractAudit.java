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
package com.yqboots.security.core.audit;

import com.yqboots.security.core.User;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.AbstractPersistable;

import javax.persistence.*;
import java.util.Date;

/**
 * Audit super class. Audit entity should extend this class for the audit needs.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@MappedSuperclass
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
public abstract class AbstractAudit extends AbstractPersistable<Long> {
    @CreatedBy
    @ManyToOne(optional = false)
    @JoinColumn(name = "CREATED_BY", nullable = false)
    private User createdBy;

    @CreatedDate
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "CREATED_DATE", nullable = false)
    private Date createdDate;

    @Column(name = "CODE", nullable = false)
    private int code = 0;

    @Lob
    @Column(name = "DESCRIPTION", nullable = true)
    private String description;

    public AbstractAudit() {
        super();
    }

    public AbstractAudit(int code) {
        super();
        this.code = code;
    }

    public User getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(final User createdBy) {
        this.createdBy = createdBy;
    }

    public Date getCreatedDate() {
        return null == createdDate ? null : new Date(createdDate.getTime());
    }

    public void setCreatedDate(final Date createdDate) {
        this.createdDate = null == createdDate ? null : new Date(createdDate.getTime());
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
