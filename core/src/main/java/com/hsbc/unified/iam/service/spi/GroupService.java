package com.hsbc.unified.iam.service.spi;

import com.hsbc.unified.iam.entity.Group;
import com.hsbc.unified.iam.entity.Realm;

public interface GroupService {
    Group createGroup(String id, String name, Realm realm, String toParent);
}
