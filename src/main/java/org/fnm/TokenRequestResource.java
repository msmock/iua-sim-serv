package org.fnm;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.jboss.logging.Logger;

// TODO validate http signature

@Path("/token")
public class TokenRequestResource {

    private static final Logger LOG = Logger.getLogger(TokenRequestParameter.class);

    @Inject
    AuthorizationService AuthorizationService;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(@Context HttpHeaders headers, MultivaluedMap<String, String> formParams) throws Exception {

        // create container for request parameter
        TokenRequestParameter tokenRequestParameter = new TokenRequestParameter();
        tokenRequestParameter.grantType = formParams.getFirst("grant_type");
        tokenRequestParameter.clientId = formParams.getFirst("client_id");
        tokenRequestParameter.clientSecret = formParams.getFirst("client_secret");
        tokenRequestParameter.principal = formParams.getFirst("principal");
        tokenRequestParameter.principalId = formParams.getFirst("principal_id");
        tokenRequestParameter.scope = formParams.getFirst("scope");
        tokenRequestParameter.personId = formParams.getFirst("person_id");

        log2Console(headers, tokenRequestParameter);

        if (!tokenRequestParameter.isComplete()) {
            return Response.status(400, "invalid_request").build();
        }

        // verify the flow parameter
        if (!"client_credentials".equals(tokenRequestParameter.grantType)) {
            return Response.status(400, "unsupported_grant_type").build();
        }

        // TODO error handling
        String jwt = AuthorizationService.getJWT(tokenRequestParameter);

        return Response.ok(jwt).build();
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

        LOG.info("Incoming request with form parameters:");
        LOG.info("grant_type : " + reqParam.grantType);
        LOG.info("client_id : " + reqParam.clientId);
        LOG.info("client_secret : " + reqParam.clientSecret);
        LOG.info("principal : " + reqParam.principal);
        LOG.info("principal_id : " + reqParam.principalId);
        LOG.info("scope : " + reqParam.scope);
        LOG.info("person_id : " + reqParam.personId);
    }

}
