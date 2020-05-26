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

import com.yqboots.security.core.Role;
import com.yqboots.security.core.RoleExistsException;
import com.yqboots.security.core.RoleManager;
import com.yqboots.security.core.RoleNotFoundException;
import com.yqboots.security.web.access.SecurityPermissions;
import com.yqboots.security.web.form.RoleForm;
import com.yqboots.security.web.form.RoleFormConverter;
import com.yqboots.web.form.SearchForm;
import com.yqboots.web.support.AbstractController;
import com.yqboots.web.support.WebKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

/**
 * Controller for {@link Role}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Controller
@RequestMapping(value = "/security/role")
public class RoleController extends AbstractController {
    private static final Logger LOG = LoggerFactory.getLogger(RoleController.class);

    private static final String REDIRECT_VIEW_PATH = "redirect:/security/role";
    private static final String VIEW_HOME = "security/role/index";
    private static final String VIEW_FORM = "security/role/form";

    @Autowired
    private RoleManager roleManager;

    @ExceptionHandler(value = {RoleExistsException.class, RoleNotFoundException.class})
    protected void handleException(Exception ex, BindingResult bindingResult) {
        bindingResult.reject(ex.getMessage());
    }

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @PreAuthorize(SecurityPermissions.ROLE_READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault final Pageable pageable,
                       final ModelMap model) {
        model.addAttribute(WebKeys.PAGE, roleManager.findRoles(searchForm.getCriterion(), pageable));
        return VIEW_HOME;
    }

    @PreAuthorize(SecurityPermissions.ROLE_WRITE)
    @RequestMapping(params = {WebKeys.ACTION_NEW}, method = RequestMethod.GET)
    public String preAdd(final ModelMap model) {
        model.addAttribute(WebKeys.MODEL, new RoleForm());
        return VIEW_FORM;
    }

    @PreAuthorize(SecurityPermissions.ROLE_WRITE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_UPDATE}, method = RequestMethod.GET)
    public String preUpdate(@RequestParam final Long id, final ModelMap model) {
        Role role = roleManager.findRole(id);

        model.addAttribute(WebKeys.MODEL, new RoleFormConverter().convert(role));
        return VIEW_FORM;
    }

    @PreAuthorize(SecurityPermissions.ROLE_WRITE)
    @RequestMapping(value = "/", method = RequestMethod.POST)
    public String update(@Valid @ModelAttribute(WebKeys.MODEL) final RoleForm domain,
                         final BindingResult bindingResult,
                         final ModelMap model) {
        if (bindingResult.hasErrors()) {
            return VIEW_FORM;
        }

        try {
            if (!domain.isExisted()) {
                Role role = new Role();
                role.setPath(domain.getPath());
                role.setAlias(domain.getAlias());
                role.setDescription(domain.getDescription());
                roleManager.addRole(role);
            } else {
                Role role = roleManager.findRole(domain.getPath());
                role.setPath(domain.getPath());
                role.setAlias(domain.getAlias());
                role.setDescription(domain.getDescription());
                roleManager.updateRole(role);
            }

            roleManager.updateUsers(domain.getPath(), domain.getUsers());
            roleManager.updateGroups(domain.getPath(), domain.getGroups());
        } catch (RoleNotFoundException e) {
            LOG.error(e.getMessage(), e);
            bindingResult.reject("SECI006");
        } catch (RoleExistsException e) {
            LOG.error(e.getMessage(), e);
            bindingResult.reject("SECI003");
        }

        if (bindingResult.hasErrors()) {
            return VIEW_FORM;
        }

        model.clear();

        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(SecurityPermissions.ROLE_DELETE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DELETE}, method = RequestMethod.GET)
    public String delete(@RequestParam final Long id, final ModelMap model) {
        roleManager.removeRole(id);
        model.clear();

        return REDIRECT_VIEW_PATH;
    }
}
