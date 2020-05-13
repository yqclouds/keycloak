package com.hsbc.unified.iam.core.service;

import com.hsbc.unified.iam.core.entity.Realm;
import com.hsbc.unified.iam.core.entity.Role;

public interface RoleService {
    Role createRole(String id, String name, Realm realm);
}
