package org.keycloak.social.fitbit;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.util.encoders.Base64;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.Charset;

public class FitbitIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    private static final String PROFILE_URL = "https://api.fitbit.com/1/user/-/profile.json";
    public static final String AUTH_URL = "https://www.fitbit.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://api.fitbit.com/oauth2/token";

    public FitbitIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode raw = SimpleHttp.doGet(PROFILE_URL, session)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .asJson();
            final JsonNode profile = raw.get("user");
            logger.debug(profile.toString());
            final String encodedId = getJsonProperty(profile, "encodedId");
            final BrokeredIdentityContext user = new BrokeredIdentityContext(encodedId);
            user.setUsername(getJsonProperty(profile, "displayName"));
            user.setName(getJsonProperty(profile, "fullName"));
            user.setIdpConfig(getConfig());
            user.setIdp(this);
            AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
            return user;
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not obtain user profile from fitbit.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "profile";
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        @GET
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            if (error != null) {
                logger.error("Failed " + getConfig().getAlias() + " broker login: " + error);
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }

            try {

                if (authorizationCode != null) {
                    String response = generateTokenRequest(authorizationCode).asString();

                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response);

                    if (getConfig().isStoreToken()) {
                        // make sure that token wasn't already set by getFederatedIdentity();
                        // want to be able to allow provider to set the token itself.
                        if (federatedIdentity.getToken() == null) {
                            federatedIdentity.setToken(response);
                        }
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(FitbitIdentityProvider.this);
                    federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode) {
            final String format = String.format("%s:%s", getConfig().getClientId(), getConfig().getClientSecret());
            final byte[] bytes = format.getBytes(Charset.forName("UTF-8"));
            return SimpleHttp.doPost(getConfig().getTokenUrl(), session)
                    .param(OAUTH2_PARAMETER_CODE, authorizationCode)
                    .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                    .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
                    .param(OAUTH2_PARAMETER_REDIRECT_URI, session.getContext().getUri().getAbsolutePath().toString())
                    .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE)
                    .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.toBase64String(bytes));
        }
    }
}
