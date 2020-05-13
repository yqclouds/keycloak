package com.hsbc.unified.iam.core.service.impl;

import com.hsbc.unified.iam.core.entity.Group;
import com.hsbc.unified.iam.core.entity.Realm;
import com.hsbc.unified.iam.core.repository.GroupRepository;
import com.hsbc.unified.iam.core.service.GroupService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class GroupServiceImpl implements GroupService {
    @Autowired
    private GroupRepository groupRepository;

    @Override
    @Transactional
    public Group createGroup(String id, String name, Realm realm, String toParent) {
        Group entity = new Group();
        entity.setId(id);
        entity.setName(name);
        entity.setRealm(realm);
        entity.setParentId(toParent == null ? Group.TOP_PARENT_ID : toParent);
        return groupRepository.saveAndFlush(entity);
    }
}
