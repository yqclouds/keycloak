package com.hsbc.unified.iam.core.service;

import com.hsbc.unified.iam.core.entity.Group;
import com.hsbc.unified.iam.core.entity.Realm;

public interface GroupService {
    Group createGroup(String id, String name, Realm realm, String toParent);
}
