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
package com.yqboots.fss.web.controller;

import com.yqboots.dict.core.DataDict;
import com.yqboots.fss.core.FileItem;
import com.yqboots.fss.core.FileItemManager;
import com.yqboots.fss.web.access.FileItemPermissions;
import com.yqboots.fss.web.form.FileUploadForm;
import com.yqboots.fss.web.form.FileUploadFormValidator;
import com.yqboots.web.form.SearchForm;
import com.yqboots.web.support.AbstractController;
import com.yqboots.web.support.WebKeys;
import com.yqboots.web.util.FileWebUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

/**
 * The controller for FileItem.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Controller
@RequestMapping(value = "/fss")
public class FileItemController extends AbstractController {
    private static final String REDIRECT_VIEW_PATH = "redirect:/fss";
    private static final String VIEW_HOME = "fss/index";
    private static final String VIEW_FORM = "fss/form";

    @Autowired
    private FileItemManager fileItemManager;

    @ModelAttribute(WebKeys.SEARCH_FORM)
    protected SearchForm<String> searchForm() {
        return new SearchForm<>();
    }

    @ModelAttribute(WebKeys.MODEL)
    protected FileUploadForm fileUploadForm() {
        return new FileUploadForm();
    }

    @PreAuthorize(FileItemPermissions.READ)
    @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST})
    public String list(@ModelAttribute(WebKeys.SEARCH_FORM) final SearchForm<String> searchForm,
                       @PageableDefault final Pageable pageable,
                       final ModelMap model) throws IOException {
        if (StringUtils.isBlank(searchForm.getCriterion())) {
            model.addAttribute(WebKeys.PAGE, new PageImpl<FileItem>(new ArrayList<>(), pageable, 0));
            return VIEW_HOME;
        }

        model.addAttribute(WebKeys.PAGE, fileItemManager.findByPath(searchForm.getCriterion(), pageable));
        return VIEW_HOME;
    }

    @PreAuthorize(FileItemPermissions.WRITE)
    @RequestMapping(params = {WebKeys.ACTION_NEW}, method = RequestMethod.GET)
    public String preAdd(final ModelMap model) {
        model.addAttribute(WebKeys.MODEL, new FileUploadForm());
        return VIEW_FORM;
    }

    @PreAuthorize(FileItemPermissions.WRITE)
    @RequestMapping(value = WebKeys.MAPPING_ROOT, method = RequestMethod.POST)
    public String update(@Valid @ModelAttribute(WebKeys.MODEL) final FileUploadForm form,
                         @PageableDefault final Pageable pageable,
                         final BindingResult bindingResult,
                         final ModelMap model) throws IOException {
        new FileUploadFormValidator().validate(form, bindingResult);
        if (bindingResult.hasErrors()) {
            model.addAttribute(WebKeys.PAGE, fileItemManager.findByPath(StringUtils.EMPTY, pageable));
            return VIEW_HOME;
        }

        final MultipartFile file = form.getFile();
        final String path = form.getPath();
        final boolean overrideExisting = form.isOverrideExisting();

        final Path destination = Paths.get(fileItemManager.getFullPath(path) + File.separator + file.getOriginalFilename());
        if (Files.exists(destination) && overrideExisting) {
            file.transferTo(destination.toFile());
        } else {
            Files.createDirectories(destination.getParent());
            Files.createFile(destination);
            file.transferTo(destination.toFile());
        }

        model.clear();
        return REDIRECT_VIEW_PATH;
    }

    @PreAuthorize(FileItemPermissions.READ)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DOWNLOAD}, method = RequestMethod.GET)
    public HttpEntity<byte[]> download(@RequestParam(WebKeys.ID) final String path) throws IOException {
        return FileWebUtils.downloadFile(fileItemManager.getFullPath(path), MediaType.APPLICATION_OCTET_STREAM);
    }

    @PreAuthorize(FileItemPermissions.DELETE)
    @RequestMapping(params = {WebKeys.ID, WebKeys.ACTION_DELETE}, method = RequestMethod.GET)
    public String delete(@RequestParam(WebKeys.ID) final String path, final ModelMap model) throws IOException {
        fileItemManager.delete(path);
        model.clear();

        return REDIRECT_VIEW_PATH;
    }
}
