package org.fnm;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.JsonParser;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TokenPostTest {

    private static final Logger LOG = Logger.getLogger(TokenPostTest.class);

    // TODO: get port from properties
    String url = "http://localhost:9000/token";

    @Test
    public void testPost() throws Exception {

        Client client = ClientBuilder.newClient();

        String requestScope = "scope=" +
                "purpose_of_use=urn:oid:2.16.756.5.30.1.127.3.10.5|AUTO" +
                "subject_role=urn:oid:2.16.756.5.30.1.127.3.10.6|TC";

        String requestPayload = "grant_type=client_credentials&" +
                "client_id=1234567890&" +
                "client_secret=abcdefg&" +
                "principal=${principal-name}&" +
                "principal_id=${principal-gln}&" +
                "person_id=${patient.epr-spid}&" +
                requestScope;

        Response response = client.target(url)
                .request()
                .header("X-Api-Key", "1234567890")
                .post(Entity.entity(requestPayload, MediaType.APPLICATION_FORM_URLENCODED), Response.class);

        // TODO: handle Errors
        LOG.info("Status: " + response.getStatus() + " " + response.getStatusInfo().getReasonPhrase());

        String token = response.readEntity(String.class);
        LOG.info(token);

        String algName = getAlgName(token);
        LOG.info("Algorithm: " + algName);

        Algorithm algorithm;
        switch (algName) {
            case "RS256" -> algorithm = getRSA();
            case "ES256" -> algorithm = getEC();
            case "HS256" -> algorithm = getHS256();
            default -> throw new IllegalStateException("Unsupported algorithm : " + algName);
        }

        JWTVerifier verifier = JWT.require(algorithm)
                .acceptLeeway(1)   // 1 sec for nbf and iat
                .acceptExpiresAt(5)   //5 secs for exp
                .build();
        DecodedJWT jwt = verifier.verify(token);

        // log payload
        String tokenPayload = new String(Base64.getUrlDecoder().decode(jwt.getPayload()));
        LOG.info("Token payload is: ");
        LOG.info(tokenPayload);

        client.close();
    }

    private String getAlgName(String token) {
        String decoded = new String(Base64.getUrlDecoder().decode(token.split("\\.")[0]));
        return JsonParser.parseString(decoded).getAsJsonObject().get("alg").getAsString();
    }

    private Algorithm getHS256() {
        return Algorithm.HMAC256("secret");
    }

    private Algorithm getRSA() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get("rsa_public_key.der"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey rsaPublicKey = (RSAPublicKey) kf.generatePublic(spec);
        return Algorithm.RSA256(rsaPublicKey);
    }

    private Algorithm getEC() throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get("ec_public_key.der"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC");
        ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(spec);
        return Algorithm.ECDSA256(publicKey);
    }


}
