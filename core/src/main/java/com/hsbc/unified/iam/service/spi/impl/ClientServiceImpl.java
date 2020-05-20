package com.hsbc.unified.iam.service.spi.impl;

import com.hsbc.unified.iam.core.util.Time;
import com.hsbc.unified.iam.entity.Client;
import com.hsbc.unified.iam.entity.ClientInitialAccess;
import com.hsbc.unified.iam.entity.Realm;
import com.hsbc.unified.iam.repository.ClientInitialAccessRepository;
import com.hsbc.unified.iam.repository.ClientRepository;
import com.hsbc.unified.iam.service.spi.ClientService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class ClientServiceImpl implements ClientService {
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private ClientInitialAccessRepository clientInitialAccessRepository;

    @Override
    @Transactional
    public Client createClient(String id, String clientId, Realm realm) {
        Client entity = new Client();
        entity.setId(id);
        entity.setClientId(clientId);
        entity.setEnabled(true);
        entity.setStandardFlowEnabled(true);
        entity.setRealm(realm);

        return clientRepository.saveAndFlush(entity);
    }

    @Override
    @Transactional
    public ClientInitialAccess createClientInitialAccess(String id, int expiration, int count, Realm realm) {
        ClientInitialAccess entity = new ClientInitialAccess();
        entity.setId(id);
        entity.setCount(count);
        entity.setRemainingCount(count);
        int currentTime = Time.currentTime();
        entity.setTimestamp(currentTime);
        entity.setExpiration(expiration);

        entity.setRealm(realm);

        return clientInitialAccessRepository.saveAndFlush(entity);
    }
}
