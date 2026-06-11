package org.fnm;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import jakarta.enterprise.context.ApplicationScoped;
import org.fnm.helper.AlgorithmHelper;
import org.fnm.helper.GrantType;
import org.fnm.helper.PurposeOfUse;
import org.fnm.helper.UserRole;
import org.fnm.model.AuthorizationRequestParameter;
import org.fnm.model.TokenRequestParameter;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 */
@ApplicationScoped
public class AuthorizationService {

    private static final Logger LOG = Logger.getLogger(AuthorizationService.class);

    public static final String SPID = "761337610411353650^^^&2.16.756.5.30.1.127.3.10.3&ISO";

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

            // if person id is null, the token is a basic access token
            if (authorizationRequestParameter.personId != null && !authorizationRequestParameter.personId.isEmpty()) {
                payload.addProperty("person_id", authorizationRequestParameter.personId);
            }

            // parse scope for role, e.g.: purpose_of_use=urn:oid:2.16.756.5.30.1.127.3.10.5|NORM subject_role=urn:oid:2.16.756.5.30.1.127.3.10.6|HCP
            String scopeS = authorizationRequestParameter.scope;
            Map<String, String> scopeMap = parseScope(scopeS);

            String role = scopeMap.get("subject_role");

            LOG.info("User role is : " + role);

            if (role == null || role.isEmpty()) throw new IllegalArgumentException("Unsupported user role : " + role);

            JsonObject extensions = buildExtensionsForRole(role, authorizationRequestParameter);
            payload.add("extensions", extensions);

            LOG.info("payload: " + payload.toString());

            return payload.toString();

        }

        throw new IllegalArgumentException("Unsupported grant type: " + tokenRequestParameter.grantType);

    }


    private JsonObject buildExtensionsForRole(String role, AuthorizationRequestParameter authorizationRequestParameter) {

        JsonObject extensions = new JsonObject();

        if (UserRole.PAT.equals(role)) {

            // always use the same spid for patients with role PAT
            JsonObject eprExtension = new JsonObject();
            eprExtension.addProperty("user_id", authorizationRequestParameter.personId);
            eprExtension.addProperty("user_id_qualifier", "urn:e-health-suisse:2015:epr-spid");
            extensions.add("ch_epr", eprExtension);

            // mock person id, name and home community id
            JsonObject iuaExtension = new JsonObject();
            iuaExtension.addProperty("subject_name", "Martina Mustermann");
            iuaExtension.addProperty("subject_role", role);
            iuaExtension.addProperty("purpose_of_use", PurposeOfUse.NORM);
            iuaExtension.addProperty("home_community_id", "urn:oid:1.2.3.4");
            iuaExtension.addProperty("person_id", authorizationRequestParameter.personId);
            extensions.add("ch_iua", iuaExtension);

        } else if (UserRole.HCP.equals(role)){

            // requires iua extension, epr extension and ch_group extension

            JsonObject eprExtension = new JsonObject();
            eprExtension.addProperty("user_id", authorizationRequestParameter.principalId);
            eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
            extensions.add("ch_epr", eprExtension);

            JsonObject iuaExtension = new JsonObject();
            iuaExtension.addProperty("subject_name", authorizationRequestParameter.principal);
            iuaExtension.addProperty("home_community_id", "${principal-community-id}");
            extensions.add("ch_iua", iuaExtension);

        } else {

            // branch for role

            JsonObject eprExtension = new JsonObject();
            eprExtension.addProperty("user_id", authorizationRequestParameter.principalId);
            eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
            extensions.add("ch_epr", eprExtension);

            JsonObject iuaExtension = new JsonObject();
            iuaExtension.addProperty("subject_name", authorizationRequestParameter.principal);
            iuaExtension.addProperty("home_community_id", "${principal-community-id}");
            extensions.add("ch_iua", iuaExtension);

        }

        return extensions;
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

    /**
     * Find the authorization request by the authorization code
     *
     * @param code the authorization code returned in the authorization request
     * @return AuthorizationRequestParameter
     */
    public AuthorizationRequestParameter findAuthorizationRequest(String code) {
        return authorizationRequests.get(code);
    }


    public Map<String, String> parseScope(String scopeString) {

        if (scopeString == null || scopeString.trim().isEmpty()) {
            return Collections.emptyMap();
        }

        // split on whitespace or commas
        String[] tokens = scopeString.trim().split("[\\s,]+");

        Map<String, String> result = new LinkedHashMap<>();
        for (String token : tokens) {

            if (token.isEmpty()) continue;
            // accept either ":" or "=" as key/value separator
            // TODO should be the minimum of both values if both are > 0
            int idx = token.indexOf('=');
            if (idx < 0) idx = token.indexOf(':');

            if (idx <0 ){
                result.put(token.trim(), "");
            } else {
                String key = token.substring(0, idx).trim();
                String val = token.substring(idx + 1).trim();
                if (!key.isEmpty()) result.put(key, val);
            }
        }
        return result;
    }

}


