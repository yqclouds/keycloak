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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.util.List;

/**
 * It defines the XML root element, which contains a list of DataDict.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DataDicts implements Serializable {
    @XmlElement(name = "dataDict", required = true)
    private List<DataDict> dataDicts;

    protected DataDicts() {
        super();
    }

    public DataDicts(final List<DataDict> dataDicts) {
        this();
        this.dataDicts = dataDicts;
    }

    public List<DataDict> getDataDicts() {
        return dataDicts;
    }

    public void setDataDicts(final List<DataDict> dataDicts) {
        this.dataDicts = dataDicts;
    }
}
