package com.hsbc.unified.iam.service.spi.impl;

import com.hsbc.unified.iam.entity.Group;
import com.hsbc.unified.iam.entity.Realm;
import com.hsbc.unified.iam.repository.GroupRepository;
import com.hsbc.unified.iam.service.spi.GroupService;
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
