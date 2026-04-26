package org.fnm;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import com.google.gson.JsonObject;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.text.ParseException;
import java.time.Instant;
import java.util.UUID;

@Path("/token")
public class TokenResource {

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(@Context HttpHeaders headers,
                          @FormParam("grant_type") String grantType,
                          @FormParam("client_id") String clientId,
                          @FormParam("client_secret") String clientSecret,
                          @FormParam("principal") String principal,
                          @FormParam("principal_id") String principalId,
                          @FormParam("person_id") String personId,
                          @FormParam("scope") String scope
    ) throws Exception {

        // create container for request parameter
        RequestParameter requestParameter = new RequestParameter();
        requestParameter.setGrantType(grantType);
        requestParameter.setClientId(clientId);
        requestParameter.setClientSecret(clientSecret);
        requestParameter.setPrincipal(principal);
        requestParameter.setPrincipalId(principalId);
        requestParameter.setScope(scope);
        requestParameter.setPersonId(personId);

        log2Console(headers, requestParameter);

        if (!requestParameter.isComplete()) {
            return Response.status(400, "invalid_request").build();
        }

        // verify the flow parameter
        if (!"client_credentials".equals(grantType)) {
            return Response.status(400, "unsupported_grant_type").build();
        }

        // TODO validate http signature

        // TODO error handling
        Algorithm algorithm = loadRSAPrivateKey();
        JsonObject payload = getJWTPayload(requestParameter);
        String jwt = JWT.create().withPayload(payload.toString()).sign(algorithm);

        return Response.ok(jwt).build();
    }

    private Algorithm loadECPrivateKey() throws ParseException, IOException, JOSEException {
        String privateKeyAsString = Files.readString(Paths.get("signature-keys/JWK-EC-pair.json"));
        JWK privateJWK = JWK.parse(privateKeyAsString);
        ECKey privateKey = privateJWK.toECKey();
        return Algorithm.ECDSA256(privateKey.toECPrivateKey());
    }

    private Algorithm loadECPublicKey() throws ParseException, IOException, JOSEException {
        String publicKeyAsString = Files.readString(Paths.get("signature-keys/JWK-EC-public-key.json"));
        JWK publicJWK = JWK.parse(publicKeyAsString);
        ECKey publicKey = publicJWK.toECKey();
        return Algorithm.ECDSA256(publicKey.toECPublicKey());
    }

    private Algorithm loadRSAPrivateKey() throws ParseException, IOException, JOSEException {
        String privateKeyAsString = Files.readString(Paths.get("signature-keys/JWK-RSA-pair.json"));
        JWK privateJWK = JWK.parse(privateKeyAsString);
        RSAKey privateKey = privateJWK.toRSAKey();
        return Algorithm.RSA256(privateKey.toRSAPrivateKey());
    }

    private Algorithm loadRSAPublicKey() throws ParseException, IOException, JOSEException {
        String publicKeyAsString = Files.readString(Paths.get("signature-keys/JWK-RSA-public-key.json"));
        JWK publicJWK = JWK.parse(publicKeyAsString);
        RSAKey publicKey = publicJWK.toRSAKey();
        return Algorithm.RSA256(publicKey.toRSAPublicKey());
    }


    /**
     * Serialize token payload as JSON
     *
     * @return payload in JSON
     */
    private static JsonObject getJWTPayload(RequestParameter requestParameter) {

        JsonObject payload = new JsonObject();

        payload.addProperty("iss", "IUATestServer");
        payload.addProperty("sub", "${entity-client-id}");
        payload.addProperty("aud", "http://ehr.ch");
        payload.addProperty("iat", Instant.now().getEpochSecond());
        payload.addProperty("nbf", Instant.now().getEpochSecond());
        payload.addProperty("exp", Instant.now().getEpochSecond() + 300);
        payload.addProperty("jti", UUID.randomUUID().toString());
        payload.addProperty("scope", requestParameter.getScope());

        JsonObject extensions = new JsonObject();

        JsonObject iuaExtension = new JsonObject();
        iuaExtension.addProperty("subject_name", requestParameter.getPrincipal());
        iuaExtension.addProperty("home_community_id", "${principal-community-id}"); // TODO read from HPD
        extensions.add("ch_iua", iuaExtension);

        JsonObject eprExtension = new JsonObject();
        eprExtension.addProperty("user_id", requestParameter.getPrincipalId());
        eprExtension.addProperty("user_id_qualifier", "urn:gs1:gln");
        extensions.add("ch_epr", eprExtension);

        payload.add("extensions", extensions);
        return payload;
    }

    /**
     */
    private static void log2Console(HttpHeaders headers, RequestParameter reqParam) {

        StringBuilder info = new StringBuilder("Request Headers:\n");

        MultivaluedMap<String, String> reqHeaders = headers.getRequestHeaders();
        reqHeaders.keySet().forEach(
                key -> info.append(key).append(":").append(reqHeaders.get(key)).append("\n")
        );

        info.append("Form parameter:\n");
        info.append("grant_type : ").append(reqParam.getGrantType()).append("\n");
        info.append("client_id : ").append(reqParam.getClientId()).append("\n");
        info.append("client_secret : ").append(reqParam.getClientSecret()).append("\n");
        info.append("principal : ").append(reqParam.getPrincipal()).append("\n");
        info.append("principal_id : ").append(reqParam.getPrincipalId()).append("\n");
        info.append("scope : ").append(reqParam.getScope()).append("\n");
        info.append("person_id : ").append(reqParam.getPersonId()).append("\n");

        System.out.println(info);
    }

}
