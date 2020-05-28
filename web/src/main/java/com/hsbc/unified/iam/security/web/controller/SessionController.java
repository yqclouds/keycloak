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

import com.hsbc.unified.iam.security.web.access.SecurityPermissions;
import com.hsbc.unified.iam.security.core.User;
import com.hsbc.unified.iam.security.core.UserManager;
import com.hsbc.unified.iam.web.form.SearchForm;
import com.hsbc.unified.iam.web.support.AbstractController;
import com.hsbc.unified.iam.web.support.WebKeys;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;

/**
 * Controller for {@link SessionInformation}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Controller
@RequestMapping(value = "/security/session")
public class SessionController extends AbstractController {
    private static final String REDIRECT_VIEW_PATH = "redirect:/security/session";
    private static final String VIEW_HOME = "security/session/index";

    @Autowired
    private SessionRegistry sessionRegistry;

    @Autowired
    private UserManager userManager;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @PreAuthorize(SecurityPermissions.SESSION_READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault final Pageable pageable,
                       final ModelMap model) {
        if (StringUtils.isBlank(searchForm.getCriterion()) || !userManager.hasUser(searchForm.getCriterion())) {
            model.addAttribute(WebKeys.PAGE, new PageImpl<SessionInformation>(new ArrayList<>(), pageable, 0));
            return VIEW_HOME;
        }

        final User user = userManager.findUser(searchForm.getCriterion());
        model.addAttribute(WebKeys.PAGE, new PageImpl<>(sessionRegistry.getAllSessions(user, true)));

        return VIEW_HOME;
    }

    @PreAuthorize(SecurityPermissions.SESSION_DELETE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DELETE}, method = RequestMethod.GET)
    public String delete(@RequestParam final String id, final ModelMap model) {
        final SessionInformation sessionInformation = sessionRegistry.getSessionInformation(id);
        if (!sessionInformation.isExpired()) {
            sessionInformation.expireNow();
        }

        model.clear();

        return REDIRECT_VIEW_PATH;
    }
}
