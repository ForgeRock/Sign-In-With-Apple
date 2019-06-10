package org.forgerock.oauth.clients.oidc;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;


/**
 * Configuration used for OpenID Connect Client Implementations.
 */
@JsonDeserialize(builder = AppleClientConfiguration.AppleBuilder.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppleClientConfiguration extends OpenIDConnectClientConfiguration {
    /**
     * Creates an OpenIDConnectClientConfiguration instance.
     *
     * @param builder OpenIDConnectClientConfiguration instance builder.
     */
    protected AppleClientConfiguration(
            Builder<?, ?> builder) {
        super(builder);
    }

    /**
     * Creates a new builder for OpenIDConnectClientConfiguration.
     *
     * @return new OpenIDConnectClientConfiguration builder instance.
     */
    @SuppressWarnings("rawtypes")
    public static Builder<? extends Builder, AppleClientConfiguration> appleClientConfiguration() {
        return new AppleBuilder();
    }

    /**
     * Gets the class name of the client implementation consuming the {@link OpenIDConnectClientConfiguration}.
     *
     * @return the client implementation class name.
     */
    @Override
    public Class<?> getClientClass() {
        return AppleClient.class;
    }


    /**
     * Wrapper around {@link Builder} to support the Jackson object mapper deserialization
     * of an OpenIDConnectClientConfiguration object.
     */
    static final class AppleBuilder
            extends AppleClientConfiguration.Builder<AppleBuilder, AppleClientConfiguration> {

        private AppleBuilder() {
            super(AppleClientConfiguration::new);
        }
    }

}
