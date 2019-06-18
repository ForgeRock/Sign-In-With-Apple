/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.oauth.clients.oidc;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper.DEFAULT_OAUTH2_SCOPE_DELIMITER;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;

import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.oauth.OAuthClient;
import org.forgerock.oauth.OAuthClientConfiguration;
import org.forgerock.oauth.UserInfo;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.SocialGoogleNode;
import org.forgerock.openam.auth.nodes.SocialOpenIdConnectNode;
import org.forgerock.openam.auth.nodes.oauth.AbstractSocialAuthLoginNode;
import org.forgerock.openam.auth.nodes.oauth.ProfileNormalizer;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.validation.URLValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = AbstractSocialAuthLoginNode.SocialAuthOutcomeProvider.class,
               configClass      = SignInWithApple.AppleConfig.class)
public class SignInWithApple extends AbstractSocialAuthLoginNode {




    /**
     * Constructs a new {@link SocialOpenIdConnectNode} with the provided {@link AbstractSocialAuthLoginNode.Config}.
     *
     * @param config           provides the settings for initialising an {@link SocialGoogleNode}.
     * @param authModuleHelper helper for oauth2
     * @param profileNormalizer User profile normaliser
     */
    @Inject
    public SignInWithApple(@Assisted AppleConfig config, SocialOAuth2Helper authModuleHelper,
                           ProfileNormalizer profileNormalizer) {
        super(config, authModuleHelper, authModuleHelper.newOAuthClient(getOAuthClientConfiguration(config)),
              profileNormalizer);
    }

    /**
     * The node config with default values for openid connect.
     */
    public interface AppleConfig extends AbstractSocialAuthLoginNode.Config {
        /**
         * the client id.
         * @return the client id
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        String clientId();

        /**
         * The client secret.
         * @return the client secret
         */
        @Attribute(order = 200, validators = {RequiredValueValidator.class})
        @Password
        char[] clientSecret();

        /**
         * The authorization endpoint.
         *
         * @return The authorization endpoint.
         */
        @Attribute(order = 300, validators = {RequiredValueValidator.class, URLValidator.class})
        default String authorizeEndpoint() {
            return "https://appleid.apple.com/auth/authorize";
        }

        /**
         * The token endpoint.
         *
         * @return The token endpoint.
         */
        @Attribute(order = 400, validators = {RequiredValueValidator.class, URLValidator.class})
        default String tokenEndpoint() {
            return "https://appleid.apple.com/auth/token";
        }

        /**
         * The userinfo endpoint.
         * @return the userinfo endpoint.
         */
        @Attribute(order = 500, validators = {URLValidator.class})
        String userInfoEndpoint();

        /**
         * The scopes to request.
         * @return the scopes.
         */
        @Attribute(order = 600, validators = {RequiredValueValidator.class})
        default String scopeString() {
            return "openid email";
        }

        /**
         * The URI the AS will redirect to.
         * @return the redirect URI
         */
        @Attribute(order = 700, validators = {RequiredValueValidator.class, URLValidator.class})
        default String redirectURI() {
            return getServerURL();
        }

        /**
         * The provider. (useful if using IDM)
         * @return the provider.
         */
        @Attribute(order = 800)
        default String provider() {
            return "Apple ID";
        }

        /**
         * The authentication id key.
         * @return the authentication id key.
         */
        @Attribute(order = 900, validators = {RequiredValueValidator.class})
        default String authenticationIdKey() {
            return "sub";
        }

        /**
         * Tells if OIDC client must identify via basic header or not.
         * @return true to authenticate via basic header, false otherwise.
         */
        @Attribute(order = 1000)
        default boolean basicAuth() {
            return false;
        }

        /**
         * The account provider class.
         * @return The account provider class.
         */
        @Attribute(order = 1100, validators = {RequiredValueValidator.class})
        default String cfgAccountProviderClass() {
            return "org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider";
        }

        /**
         * The account mapper class.
         * @return the account mapper class.
         */
        @Attribute(order = 1200, validators = {RequiredValueValidator.class})
        default String cfgAccountMapperClass() {
            return "org.forgerock.openam.authentication.modules.oidc.JwtAttributeMapper|*|openid-";
        }

        /**
         * The attribute mapping classes.
         * @return the attribute mapping classes.
         */
        @Attribute(order = 1300, validators = {RequiredValueValidator.class})
        default Set<String> cfgAttributeMappingClasses() {
            return singleton("org.forgerock.openam.authentication.modules.oidc"
                                     + ".JwtAttributeMapper|iplanet-am-user-alias-list|openid-");
        }

        /**
         * The account mapper configuration.
         * @return the account mapper configuration.
         */
        @Attribute(order = 1400, validators = {RequiredValueValidator.class})
        default Map<String, String> cfgAccountMapperConfiguration() {
            return singletonMap("sub", "iplanet-am-user-alias-list");
        }

        /**
         * The attribute mapping configuration.
         * @return the attribute mapping configuration
         */
        @Attribute(order = 1500, validators = {RequiredValueValidator.class})
        default Map<String, String> cfgAttributeMappingConfiguration() {
            return singletonMap("sub", "iplanet-am-user-alias-list");
        }

        /**
         * Specifies if the user attributes must be saved in session.
         * @return true to save the user attribute into the session, false otherwise.
         */
        @Attribute(order = 1600)
        default boolean saveUserAttributesToSession() {
            return true;
        }

        /**
         * Specify if the mixup mitigation must be activated.
         * The mixup mitigation add an extra level of security by checking the client_id and iss coming from the
         * authorizeEndpoint response.
         *
         * @return true to activate it , false otherwise
         */
        @Attribute(order = 1700)
        default boolean cfgMixUpMitigation() {
            return false;
        }

        /**
         * The issuer. Must be specified to use mixup mitigation.
         * @return the issuer.
         */
        @Attribute(order = 1800)
        default String issuer() {
            return "https://appleid.apple.com";
        }
        /**
         * The openid connect validation method.
         * @return the openid connect validation method.
         */
        @Attribute(order = 1900, validators = {RequiredValueValidator.class})
        default SocialOpenIdConnectNode.OpenIDValidationMethod openIdValidationMethod() {
            return SocialOpenIdConnectNode.OpenIDValidationMethod.JWK_URL;
        }


        /**
         * The openid connect validation value.
         *
         * @return the openid validation value.
         */
        @Attribute(order = 2000)
        default String openIdValidationValue() {
            return "https://appleid.apple.com/auth/keys";
        }

    }


    private static OAuthClientConfiguration getOAuthClientConfiguration(AppleConfig config) {
        AppleClientConfiguration.Builder<?, AppleClientConfiguration> builder =
                AppleClientConfiguration.appleClientConfiguration();
        builder.withClientId(config.clientId())
               .withClientSecret(new String(config.clientSecret()))
               .withAuthorizationEndpoint(config.authorizeEndpoint())
               .withTokenEndpoint(config.tokenEndpoint())
               .withScope(Collections.singletonList(config.scopeString()))
               .withScopeDelimiter(DEFAULT_OAUTH2_SCOPE_DELIMITER)
               .withBasicAuth(config.basicAuth())
               .withUserInfoEndpoint(config.userInfoEndpoint())
               .withRedirectUri(URI.create(config.redirectURI()))
               .withProvider(config.provider())
               .withIssuer(config.issuer())
               .withAuthenticationIdKey(config.authenticationIdKey())
               .build();

        if (config.openIdValidationMethod().equals(SocialOpenIdConnectNode.OpenIDValidationMethod.JWK_URL)) {
            builder.withJwk(config.openIdValidationValue());
        } else if (config.openIdValidationMethod().equals(SocialOpenIdConnectNode.OpenIDValidationMethod.WELL_KNOWN_URL)) {
            builder.withWellKnownEndpoint(config.openIdValidationValue());
        }

        return builder.build();
    }

    /**
     * Overriding this method to return JWT claims if the user info is of type OpenIDConnectUserInfo.
     * @param userInfo The user information.
     * @return The jwt claims.
     */
    @Override
    protected JwtClaimsSet getJwtClaims(UserInfo userInfo) {
        return userInfo instanceof OpenIDConnectUserInfo ? ((OpenIDConnectUserInfo) userInfo).getJwtClaimsSet()
                : super.getJwtClaims(userInfo);
    }

}
