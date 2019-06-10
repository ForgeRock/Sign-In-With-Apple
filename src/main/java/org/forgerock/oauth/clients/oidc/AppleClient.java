package org.forgerock.oauth.clients.oidc;

import static org.forgerock.http.protocol.Responses.noopExceptionFunction;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth.DataStore;
import org.forgerock.oauth.InvalidOAuthRequestException;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.resolvers.service.OpenIdResolverService;
import org.forgerock.oauth.resolvers.service.OpenIdResolverServiceConfigurator;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Reject;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.time.TimeService;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.Map;

public class AppleClient extends OpenIDConnectClient {

    public AppleClient(Handler httpHandler,
                       AppleClientConfiguration config, TimeService timeService,
                       SecureRandom random) {
        super(httpHandler, config, timeService, random);
    }

    public AppleClient(Handler httpHandler,
                       AppleClientConfiguration config, Clock clock,
                       SecureRandom random) {
        super(httpHandler, config, clock, random);
    }

    @Override
    public Promise<JsonValue, OAuthException> handlePostAuth(
            final DataStore dataStore,
            final Map<String, List<String>> requestParameters) {

        // verify required request params
        final String code = getFirstValueOrNull(requestParameters.get(CODE));
        Reject.ifNull(code, "Authorization call-back failed because there was no value provided for the code param.");
        final String state = getFirstValueOrNull(requestParameters.get(STATE));
        Reject.ifNull(state, "Authorization call-back failed because there was no value for the state param.");

        final JsonValue storedData;
        try {
            storedData = dataStore.retrieveData();
        } catch (OAuthException e) {
            return e.asPromise();
        }

        final String expectedState = storedData.get(STATE).required().asString();
        if (!expectedState.equals(state)) {
            return new InvalidOAuthRequestException("Authorization call-back failed because the state "
                                                            + "parameter contained an unexpected value").asPromise();
        }

        Request request = createRequestForTokenEndpoint(code);
        return httpHandler
                .handle(new RootContext(), request)
                .thenAlways(closeSilentlyAsync(request))
                .then(closeSilently(mapToJsonValue()), noopExceptionFunction())
                .then(addExpireTime)
                .then(storeResponse(dataStore))
                .then(createPostAuthResponse(storedData));
    }
}
