package com.hsbc.unified.iam.core.service;

import com.hsbc.unified.iam.core.entity.Client;
import com.hsbc.unified.iam.core.entity.ClientInitialAccess;
import com.hsbc.unified.iam.core.entity.Realm;

public interface ClientService {
    Client createClient(String id, String clientId, Realm realm);

    ClientInitialAccess createClientInitialAccess(String id, int expiration, int count, Realm realm);
}
