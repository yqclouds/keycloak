package org.keycloak.config.providers;

import org.keycloak.protocol.docker.mapper.AllowAllDockerProtocolMapper;
import org.keycloak.protocol.oidc.mappers.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ProtocolMapperConfiguration {
    @Bean
    public AllowAllDockerProtocolMapper allowAllDockerProtocolMapper() {
        return new AllowAllDockerProtocolMapper();
    }

    @Bean
    public AllowedWebOriginsProtocolMapper allowedWebOriginsProtocolMapper() {
        return new AllowedWebOriginsProtocolMapper();
    }

    @Bean
    public GroupMembershipMapper oidcGroupMembershipMapper() {
        return new GroupMembershipMapper();
    }

    @Bean
    public AudienceProtocolMapper audienceProtocolMapper() {
        return new AudienceProtocolMapper();
    }

    @Bean
    public FullNameMapper fullNameMapper() {
        return new FullNameMapper();
    }

    @Bean
    public AddressMapper addressMapper() {
        return new AddressMapper();
    }

    @Bean
    public ScriptBasedOIDCProtocolMapper deployedScriptOIDCProtocolMapper() {
        return new ScriptBasedOIDCProtocolMapper();
    }

    @Bean
    public HardcodedRole hardcodedRole() {
        return new HardcodedRole();
    }

    @Bean
    public RoleNameMapper roleNameMapper() {
        return new RoleNameMapper();
    }

    @Bean
    public SHA256PairwiseSubMapper sha256PairwiseSubMapper() {
        return new SHA256PairwiseSubMapper();
    }

    @Bean
    public UserAttributeMapper userAttributeMapper() {
        return new UserAttributeMapper();
    }

    @Bean
    public UserSessionNoteMapper userSessionNoteMapper() {
        return new UserSessionNoteMapper();
    }

    @Bean
    public UserPropertyMapper userPropertyMapper() {
        return new UserPropertyMapper();
    }

    @Bean
    public UserClientRoleMappingMapper userClientRoleMappingMapper() {
        return new UserClientRoleMappingMapper();
    }

    @Bean
    public UserRealmRoleMappingMapper userRealmRoleMappingMapper() {
        return new UserRealmRoleMappingMapper();
    }
}
