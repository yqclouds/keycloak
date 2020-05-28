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
package com.hsbc.unified.iam.security.web.controller;

import com.hsbc.unified.iam.security.core.Permission;
import com.hsbc.unified.iam.security.core.PermissionManager;
import com.hsbc.unified.iam.security.web.access.SecurityPermissions;
import com.hsbc.unified.iam.web.form.SearchForm;
import com.hsbc.unified.iam.web.support.AbstractController;
import com.hsbc.unified.iam.web.support.WebKeys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Controller for {@link Permission}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Controller
@RequestMapping(value = "/security/permission")
public class PermissionController extends AbstractController {
    // private static final String REDIRECT_VIEW_PATH = "redirect:/security/permission";
    private static final String VIEW_HOME = "security/permission/index";

    @Autowired
    private PermissionManager permissionManager;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @PreAuthorize(SecurityPermissions.PERMISSION_READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault(sort = {"securityIdentity", "objectIdIdentity", "objectIdClass", "mask"}) final Pageable pageable,
                       final ModelMap model) {
        model.addAttribute(WebKeys.PAGE, permissionManager.findPermissions(searchForm.getCriterion(), pageable));
        return VIEW_HOME;
    }
}
