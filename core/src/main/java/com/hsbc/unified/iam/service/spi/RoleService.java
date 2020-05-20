package com.hsbc.unified.iam.service.spi;

import com.hsbc.unified.iam.entity.Client;
import com.hsbc.unified.iam.entity.Realm;
import com.hsbc.unified.iam.entity.Role;

public interface RoleService {
    Role createRole(String id, String name, Realm realm);

    Role createRole(String id, String name, Client client, String realm);
}
