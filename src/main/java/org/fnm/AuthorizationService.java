package org.fnm;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import jakarta.enterprise.context.ApplicationScoped;
import org.fnm.helper.AlgorithmHelper;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TODO: implement authorization code flow token request
 * TODO: validate the idp assertion in the token request
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
        JsonObject payload = buildJWTPayload(tokenRequestParameter);
        return JWT.create().withPayload(payload.toString()).sign(algorithm);
    }

    /**
     * TODO: extend to support authorization code flow
     *
     * @return token payload as JSON
     */
    private JsonObject buildJWTPayload(TokenRequestParameter tokenRequestParameter) {

        JsonObject payload = new JsonObject();

        payload.addProperty("iss", "IUATestServer");
        payload.addProperty("sub", "${entity-client-id}");
        payload.addProperty("aud", "http://ehr.ch");
        payload.addProperty("iat", Instant.now().getEpochSecond());
        payload.addProperty("nbf", Instant.now().getEpochSecond());
        payload.addProperty("exp", Instant.now().getEpochSecond() + 300);
        payload.addProperty("jti", UUID.randomUUID().toString());
        payload.addProperty("scope", tokenRequestParameter.scope);

        JsonObject extensions = new JsonObject();

        JsonObject iuaExtension = new JsonObject();
        iuaExtension.addProperty("subject_name", tokenRequestParameter.principal);
        iuaExtension.addProperty("home_community_id", "${principal-community-id}"); // TODO read from HPD
        extensions.add("ch_iua", iuaExtension);

        JsonObject eprExtension = new JsonObject();
        eprExtension.addProperty("user_id", tokenRequestParameter.principalId);
        eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
        extensions.add("ch_epr", eprExtension);

        payload.add("extensions", extensions);
        return payload;
    }

    /**
     * Register the authorization request from the authorization code flow
     *
     * @param code the authorization code
     * @param requestParameter the authorization request parameter
     */
    public void register(String code, AuthorizationRequestParameter requestParameter) {
        authorizationRequests.put(code, requestParameter);
    }
}
