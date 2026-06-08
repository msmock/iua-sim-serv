package org.fnm;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import jakarta.enterprise.context.ApplicationScoped;
import org.fnm.helper.AlgorithmHelper;
import org.fnm.helper.GrantType;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 */
@ApplicationScoped
public class AuthorizationService {

    private static final Logger LOG = Logger.getLogger(AuthorizationService.class);

    // container for the authorization requests
    private final Map<String, AuthorizationRequestParameter> authorizationRequests = new ConcurrentHashMap<>();

    /**
     * @return the JWT as string
     */
    public String buildJWT(TokenRequestParameter tokenRequestParameter) throws ParseException, IOException, JOSEException {
        Algorithm algorithm = AlgorithmHelper.loadRSAPrivateKey();
        String payload = buildJWTPayload(tokenRequestParameter);
        return JWT.create().withPayload(payload).sign(algorithm);
    }

    /**
     * TODO: extend to support authorization code flow
     *
     * @return token payload as JSON string
     */
    private String buildJWTPayload(TokenRequestParameter tokenRequestParameter) {

        // check the grant type
        if (tokenRequestParameter.grantType.equals(GrantType.clientCredentials)) {

            JsonObject payload = new JsonObject();
            payload.addProperty("iss", "IUATestServer");
            payload.addProperty("sub", tokenRequestParameter.clientId);
            payload.addProperty("aud", "http://ehr.ch");
            payload.addProperty("iat", Instant.now().getEpochSecond());
            payload.addProperty("nbf", Instant.now().getEpochSecond());
            payload.addProperty("exp", Instant.now().getEpochSecond() + 300);
            payload.addProperty("jti", UUID.randomUUID().toString());
            payload.addProperty("scope", tokenRequestParameter.scope);
            payload.addProperty("person_id", tokenRequestParameter.personId);

            JsonObject extensions = new JsonObject();

            JsonObject eprExtension = new JsonObject();
            eprExtension.addProperty("user_id", tokenRequestParameter.principalId);
            eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
            extensions.add("ch_epr", eprExtension);

            JsonObject iuaExtension = new JsonObject();
            iuaExtension.addProperty("subject_name", tokenRequestParameter.principal);
            iuaExtension.addProperty("home_community_id", "${principal-community-id}");
            extensions.add("ch_iua", iuaExtension);

            payload.add("extensions", extensions);
            return payload.toString();

        } else if (tokenRequestParameter.grantType.equals(GrantType.authorizationCode)) {

            // throw exception if the authorization code is not registered
            String authorizationCode = tokenRequestParameter.code;
            AuthorizationRequestParameter authorizationRequestParameter = authorizationRequests.get(authorizationCode);
            if (authorizationRequestParameter == null) {
                throw new IllegalArgumentException("Unknown authorization code");
            }

            // verify the client assertion
            String clientAssertion = tokenRequestParameter.clientAssertion;
            LOG.info("clientAssertion: " + clientAssertion);

            // TODO verify signature and read the user ID

            // TODO parse scope for role

            // build payload
            JsonObject payload = new JsonObject();
            payload.addProperty("iss", "IUATestServer");
            payload.addProperty("sub", tokenRequestParameter.clientId);
            payload.addProperty("aud", "http://ehr.ch");
            payload.addProperty("iat", Instant.now().getEpochSecond());
            payload.addProperty("nbf", Instant.now().getEpochSecond());
            payload.addProperty("exp", Instant.now().getEpochSecond() + 300);
            payload.addProperty("jti", UUID.randomUUID().toString());

            payload.addProperty("scope", authorizationRequestParameter.scope);
            payload.addProperty("person_id", authorizationRequestParameter.personId);

            JsonObject extensions = new JsonObject();

            // TODO depends on user role
            JsonObject eprExtension = new JsonObject();
            eprExtension.addProperty("user_id", authorizationRequestParameter.principalId);
            eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
            extensions.add("ch_epr", eprExtension);

            JsonObject iuaExtension = new JsonObject();
            iuaExtension.addProperty("subject_name", authorizationRequestParameter.principal);
            iuaExtension.addProperty("home_community_id", "${principal-community-id}");
            extensions.add("ch_iua", iuaExtension);

            payload.add("extensions", extensions);
            return payload.toString();

        }

        throw new IllegalArgumentException("Unsupported grant type: " + tokenRequestParameter.grantType);

    }

    /**
     * Register the authorization request from the authorization code flow
     *
     * @param code             the authorization code
     * @param requestParameter the authorization request parameter
     */
    public void registerAuthorizationRequest(String code, AuthorizationRequestParameter requestParameter) {
        authorizationRequests.put(code, requestParameter);
    }
}
