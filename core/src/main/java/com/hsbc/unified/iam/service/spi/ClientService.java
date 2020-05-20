package com.hsbc.unified.iam.service.spi;

import com.hsbc.unified.iam.entity.Client;
import com.hsbc.unified.iam.entity.ClientInitialAccess;
import com.hsbc.unified.iam.entity.Realm;

public interface ClientService {
    Client createClient(String id, String clientId, Realm realm);

    ClientInitialAccess createClientInitialAccess(String id, int expiration, int count, Realm realm);
}
