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
package com.yqboots.dict.web.controller;

import com.yqboots.dict.core.DataDict;
import com.yqboots.dict.core.DataDictExistsException;
import com.yqboots.dict.core.DataDictManager;
import com.yqboots.dict.web.access.DataDictPermissions;
import com.yqboots.dict.web.form.DataDictSearchForm;
import com.yqboots.dict.web.form.FileUploadForm;
import com.yqboots.dict.web.form.FileUploadFormValidator;
import com.yqboots.web.form.SearchForm;
import com.yqboots.web.support.AbstractController;
import com.yqboots.web.support.WebKeys;
import com.yqboots.web.util.FileWebUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.oxm.XmlMappingException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.validation.Valid;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

/**
 * The main Controller for DataDict.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Controller
@RequestMapping(value = "/dict")
public class DataDictController extends AbstractController {
    private static final String REDIRECT_VIEW_PATH = "redirect:/dict";
    private static final String VIEW_HOME = "dict/index";
    private static final String VIEW_FORM = "dict/form";

    @Autowired
    private DataDictManager dataDictManager;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<DataDictSearchForm> searchForm() {
        SearchForm<DataDictSearchForm> result = new SearchForm<>();
        result.setCriterion(new DataDictSearchForm());
        return result;
    }

    @ModelAttribute(WebKeys.FILE_UPLOAD_FORM)
    protected FileUploadForm fileUploadForm() {
        return new FileUploadForm();
    }

    @PreAuthorize(DataDictPermissions.READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<DataDictSearchForm> searchForm,
                       @PageableDefault(sort = {"name", "text", "value"}) final Pageable pageable,
                       final ModelMap model) {
        final DataDictSearchForm _searchForm = searchForm.getCriterion();

        String criterion = _searchForm.getName();
        if (StringUtils.isNotBlank(_searchForm.getLocale())) {
            criterion = _searchForm.getName() + "_" + _searchForm.getLocale();
        }

        model.addAttribute(WebKeys.PAGE, dataDictManager.getDataDicts(criterion, pageable));
        return VIEW_HOME;
    }

    @PreAuthorize(DataDictPermissions.WRITE)
    @RequestMapping(params = {WebKeys.ACTION_NEW}, method = RequestMethod.GET)
    public String preAdd(final ModelMap model) {
        model.addAttribute(WebKeys.MODEL, new DataDict());
        return VIEW_FORM;
    }

    @PreAuthorize(DataDictPermissions.WRITE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_UPDATE}, method = RequestMethod.GET)
    public String preUpdate(@RequestParam final Long id, final ModelMap model) {
        model.addAttribute(WebKeys.MODEL, dataDictManager.getDataDict(id));
        return VIEW_FORM;
    }

    @PreAuthorize(DataDictPermissions.WRITE)
    @RequestMapping(value = WebKeys.MAPPING_ROOT, method = RequestMethod.POST)
    public String update(@Valid @ModelAttribute(WebKeys.MODEL) final DataDict dict,
                         final BindingResult bindingResult,
                         final ModelMap model) {
        if (bindingResult.hasErrors()) {
            return VIEW_FORM;
        }

        try {
            dataDictManager.update(dict);
        } catch (DataDictExistsException e) {
            bindingResult.reject("I0001");
            return VIEW_FORM;
        }

        model.clear();

        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(DataDictPermissions.DELETE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DELETE}, method = RequestMethod.GET)
    public String delete(@RequestParam final Long id, final ModelMap model) {
        dataDictManager.delete(id);
        model.clear();

        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(DataDictPermissions.WRITE)
    @RequestMapping(value = WebKeys.MAPPING_IMPORTS, method = RequestMethod.POST)
    public String imports(@ModelAttribute(WebKeys.FILE_UPLOAD_FORM) FileUploadForm fileUploadForm,
                          @PageableDefault final Pageable pageable,
                          final BindingResult bindingResult,
                          final ModelMap model) throws IOException {
        new FileUploadFormValidator().validate(fileUploadForm, bindingResult);
        if (bindingResult.hasErrors()) {
            model.addAttribute(WebKeys.PAGE, dataDictManager.getDataDicts(StringUtils.EMPTY, pageable));
            return VIEW_HOME;
        }

        try (final InputStream inputStream = fileUploadForm.getFile().getInputStream()) {
            dataDictManager.imports(inputStream);
        } catch (XmlMappingException e) {
            bindingResult.rejectValue(WebKeys.FILE, "I0003");
        }

        if (bindingResult.hasErrors()) {
            model.addAttribute(WebKeys.PAGE, dataDictManager.getDataDicts(StringUtils.EMPTY, pageable));
            return VIEW_HOME;
        }

        model.clear();

        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(DataDictPermissions.READ)
    @RequestMapping(value = WebKeys.MAPPING_EXPORTS, method = {RequestMethod.GET, RequestMethod.POST})
    public HttpEntity<byte[]> exports() throws IOException {
        final Path path = dataDictManager.exports();

        return FileWebUtils.downloadFile(path, MediaType.APPLICATION_XML);
    }
}
