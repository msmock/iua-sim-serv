package org.fnm;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;

import java.util.Base64;
import java.util.List;

// TODO validate http signature
// TODO validate client_id and client_secret from http authorization header

@Path("/token")
public class TokenRequestResource {

    private static final Logger LOG = Logger.getLogger(TokenRequestParameter.class);

    @Inject
    AuthorizationService AuthorizationService;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(@Context HttpHeaders headers, MultivaluedMap<String, String> formParams) throws Exception {

        // get authorization header
        MultivaluedMap<String, String> requestHeaders = headers.getRequestHeaders();
        String authHeader = requestHeaders.getFirst("Authorization");
        List<String> headerData = parseAuthorizationHeader(authHeader);

        // create container for request parameter
        TokenRequestParameter tokenRequestParameter = new TokenRequestParameter();

        // common for both types
        tokenRequestParameter.grantType = formParams.getFirst("grant_type");
        tokenRequestParameter.clientId = headerData.get(0);
        tokenRequestParameter.clientSecret = headerData.get(1);

        // CC flow only
        tokenRequestParameter.principal = formParams.getFirst("principal");
        tokenRequestParameter.principalId = formParams.getFirst("principal_id");
        tokenRequestParameter.scope = formParams.getFirst("scope");
        tokenRequestParameter.personId = formParams.getFirst("person_id");

        // AC flow only
        tokenRequestParameter.code = formParams.getFirst("code");
        tokenRequestParameter.clientAssertionType = formParams.getFirst("client_assertion_type");
        tokenRequestParameter.clientAssertion = formParams.getFirst("client_assertion");

        log2Console(headers, tokenRequestParameter);

        if (!tokenRequestParameter.isComplete()) {
            return Response.status(400, "invalid_request").build();
        }
        
        if ("client_credentials".equals(tokenRequestParameter.grantType) ||
                "code".equals(tokenRequestParameter.grantType)){
            String jwt = AuthorizationService.buildJWT(tokenRequestParameter);
            return Response.ok(jwt).build();
        } else {
            return Response.status(400, "unsupported_grant_type").build();
        }

    }

    /**
     *
     */
    private static void log2Console(HttpHeaders headers, TokenRequestParameter reqParam) {

        LOG.info("Incoming request:");
        LOG.info("Header data:");

        MultivaluedMap<String, String> requestHeaders = headers.getRequestHeaders();
        requestHeaders.keySet().forEach(
                key -> LOG.info(key + ":" + requestHeaders.get(key))
        );

        LOG.info("Form parameters:");
        LOG.info("grant_type : " + reqParam.grantType);
        LOG.info("client_id : " + reqParam.clientId);
        LOG.info("client_secret : " + reqParam.clientSecret);
        LOG.info("principal : " + reqParam.principal);
        LOG.info("principal_id : " + reqParam.principalId);
        LOG.info("scope : " + reqParam.scope);
        LOG.info("person_id : " + reqParam.personId);
    }

    private List<String> parseAuthorizationHeader(String authHeader) {

        // Check if the header starts with "Basic "
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            // Extract the Base64 encoded part
            String base64Credentials = authHeader.substring("Basic ".length()).trim();

            // Decode the Base64 string
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));

            // Split the credentials into client_id and client_secret
            String[] values = credentials.split(":", 2);
            String clientId = values[0];
            String clientSecret = values[1];

            // Output the results
            LOG.info("Client ID: " + clientId);
            LOG.info("Client Secret: " + clientSecret);

            return List.of(clientId, clientSecret);

        } else {
            LOG.info("Invalid Authorization header");
            return List.of();
        }

    }

}
