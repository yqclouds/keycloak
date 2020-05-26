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
package com.yqboots.security.web.controller;

import com.yqboots.security.core.audit.repository.SecurityAuditRepository;
import com.yqboots.security.web.access.SecurityPermissions;
import com.yqboots.web.form.SearchForm;
import com.yqboots.web.support.AbstractController;
import com.yqboots.web.support.WebKeys;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Controller for {@link com.yqboots.security.core.audit.SecurityAudit}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Controller
@RequestMapping(value = "/security/audit")
public class AuditController extends AbstractController {
    private static final String VIEW_HOME = "security/audit/index";

    @Autowired
    private SecurityAuditRepository securityAuditRepository;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @PreAuthorize(SecurityPermissions.AUDIT_READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault(sort = {"createdDate"}, direction = Sort.Direction.DESC) final Pageable pageable,
                       final ModelMap model) {
        if (StringUtils.isBlank(searchForm.getCriterion())) {
            model.addAttribute(WebKeys.PAGE, securityAuditRepository.findAll(pageable));
            return VIEW_HOME;
        }

        model.addAttribute(WebKeys.PAGE, securityAuditRepository.findByTarget(searchForm.getCriterion(), pageable));
        return VIEW_HOME;
    }
}
