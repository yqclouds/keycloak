package org.keycloak.protocol.oidc.mappers;

import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperUtils;
import org.keycloak.protocol.oidc.utils.PairwiseSubMapperValidator;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.LinkedList;
import java.util.List;

/**
 * Set the 'sub' claim to pairwise .
 *
 * @author <a href="mailto:martin.hardselius@gmail.com">Martin Hardselius</a>
 */
public abstract class AbstractPairwiseSubMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID_SUFFIX = "-pairwise-sub-mapper";

    @Autowired
    private PairwiseSubMapperValidator pairwiseSubMapperValidator;

    public abstract String getIdPrefix();

    /**
     * Generates a pairwise subject identifier.
     *
     * @param mappingModel
     * @param sectorIdentifier client sector identifier
     * @param localSub         local subject identifier (user id)
     * @return A pairwise subject identifier
     */
    public abstract String generateSub(ProtocolMapperModel mappingModel, String sectorIdentifier, String localSub);

    /**
     * Override to add additional provider configuration properties. By default, a pairwise sub mapper will only contain configuration for a sector identifier URI.
     *
     * @return A list of provider configuration properties.
     */
    public List<ProviderConfigProperty> getAdditionalConfigProperties() {
        return new LinkedList<>();
    }

    /**
     * Override to add additional configuration validation. Called when instance of mapperModel is created/updated for this protocolMapper through admin endpoint.
     *
     * @param realm
     * @param mapperContainer client or clientScope
     * @param mapperModel
     * @throws ProtocolMapperConfigException if configuration provided in mapperModel is not valid
     */
    public void validateAdditionalConfig(RealmModel realm, ProtocolMapperContainerModel mapperContainer, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
    }

    @Override
    public final String getDisplayCategory() {
        return AbstractOIDCProtocolMapper.TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setIDTokenSubject(token, generateSub(mappingModel, getSectorIdentifier(clientSessionCtx.getClientSession().getClient(), mappingModel), userSession.getUser().getId()));
        return token;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setAccessTokenSubject(token, generateSub(mappingModel, getSectorIdentifier(clientSessionCtx.getClientSession().getClient(), mappingModel), userSession.getUser().getId()));
        return token;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        setUserInfoTokenSubject(token, generateSub(mappingModel, getSectorIdentifier(clientSessionCtx.getClientSession().getClient(), mappingModel), userSession.getUser().getId()));
        return token;
    }

    protected void setIDTokenSubject(IDToken token, String pairwiseSub) {
        token.setSubject(pairwiseSub);
    }

    protected void setAccessTokenSubject(IDToken token, String pairwiseSub) {
        token.setSubject(pairwiseSub);
    }

    protected void setUserInfoTokenSubject(IDToken token, String pairwiseSub) {
        token.getOtherClaims().put("sub", pairwiseSub);
    }

    @Override
    public final List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new LinkedList<>();
        configProperties.add(PairwiseSubMapperHelper.createSectorIdentifierConfig());
        configProperties.addAll(getAdditionalConfigProperties());
        return configProperties;
    }

    private String getSectorIdentifier(ClientModel client, ProtocolMapperModel mappingModel) {
        String sectorIdentifierUri = PairwiseSubMapperHelper.getSectorIdentifierUri(mappingModel);
        if (sectorIdentifierUri != null && !sectorIdentifierUri.isEmpty()) {
            return PairwiseSubMapperUtils.resolveValidSectorIdentifier(sectorIdentifierUri);
        }
        return PairwiseSubMapperUtils.resolveValidSectorIdentifier(client.getRootUrl(), client.getRedirectUris());
    }

    @Override
    public final void validateConfig(RealmModel realm, ProtocolMapperContainerModel mapperContainer, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        ClientModel client = null;
        if (mapperContainer instanceof ClientModel) {
            client = (ClientModel) mapperContainer;
            pairwiseSubMapperValidator.validate(client, mapperModel);
        }
        validateAdditionalConfig(realm, mapperContainer, mapperModel);
    }

    @Override
    public final String getId() {
        return "oidc-" + getIdPrefix() + PROVIDER_ID_SUFFIX;
    }
}