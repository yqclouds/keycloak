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

import com.hsbc.unified.iam.security.core.GroupExistsException;
import com.hsbc.unified.iam.security.web.access.SecurityPermissions;
import com.hsbc.unified.iam.security.web.form.GroupForm;
import com.hsbc.unified.iam.security.web.form.GroupFormConverter;
import com.hsbc.unified.iam.security.core.Group;
import com.hsbc.unified.iam.security.core.GroupManager;
import com.hsbc.unified.iam.security.core.GroupNotFoundException;
import com.hsbc.unified.iam.web.form.SearchForm;
import com.hsbc.unified.iam.web.support.AbstractController;
import com.hsbc.unified.iam.web.support.WebKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;

/**
 * Controller for {@link Group}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Controller
@RequestMapping(value = "/security/group")
public class GroupController extends AbstractController {
    private static final Logger LOG = LoggerFactory.getLogger(GroupController.class);

    private static final String REDIRECT_VIEW_PATH = "redirect:/security/group";
    private static final String VIEW_HOME = "security/group/index";
    private static final String VIEW_FORM = "security/group/form";

    @Autowired
    private GroupManager groupManager;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @PreAuthorize(SecurityPermissions.GROUP_READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault final Pageable pageable,
                       final ModelMap model) {
        model.addAttribute(WebKeys.PAGE, groupManager.findGroups(searchForm.getCriterion(), pageable));
        return VIEW_HOME;
    }

    @PreAuthorize(SecurityPermissions.GROUP_WRITE)
    @RequestMapping(params = {WebKeys.ACTION_NEW}, method = RequestMethod.GET)
    public String preAdd(final ModelMap model) {
        model.addAttribute(WebKeys.MODEL, new GroupForm());
        return VIEW_FORM;
    }

    @PreAuthorize(SecurityPermissions.GROUP_WRITE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_UPDATE}, method = RequestMethod.GET)
    public String preUpdate(@RequestParam final Long id, final ModelMap model) {
        Group group = groupManager.findGroup(id);

        model.addAttribute(WebKeys.MODEL, new GroupFormConverter().convert(group));
        return VIEW_FORM;
    }

    @PreAuthorize(SecurityPermissions.GROUP_WRITE)
    @RequestMapping(value = "/", method = RequestMethod.POST)
    public String update(@Valid @ModelAttribute(WebKeys.MODEL) final GroupForm domain,
                         final BindingResult bindingResult,
                         final ModelMap model) {
        if (bindingResult.hasErrors()) {
            return VIEW_FORM;
        }

        try {
            if (!domain.isExisted()) {
                Group group = new Group();
                group.setPath(domain.getPath());
                group.setAlias(domain.getAlias());
                group.setDescription(domain.getDescription());
                groupManager.addGroup(group);
            } else {
                Group group = groupManager.findGroup(domain.getPath());
                group.setAlias(domain.getAlias());
                group.setDescription(domain.getDescription());
                groupManager.updateGroup(group);
            }

            groupManager.updateUsers(domain.getPath(), domain.getUsers());
            groupManager.updateRoles(domain.getPath(), domain.getRoles());
        } catch (final GroupNotFoundException e) {
            LOG.error(e.getMessage(), e);
            bindingResult.reject("SECI005");
        } catch (final GroupExistsException e) {
            LOG.error(e.getMessage(), e);
            bindingResult.reject("SECI002");
        }

        if (bindingResult.hasErrors()) {
            return VIEW_FORM;
        }

        model.clear();

        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(SecurityPermissions.GROUP_DELETE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DELETE}, method = RequestMethod.GET)
    public String delete(@RequestParam final Long id, final ModelMap model) {
        groupManager.removeGroup(id);
        model.clear();

        return REDIRECT_VIEW_PATH;
    }
}
