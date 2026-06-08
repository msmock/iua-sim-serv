package org.fnm;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.UUID;

@Path("/authorize")
public class AuthorizationRequestResource {

    private static final Logger LOG = Logger.getLogger(TokenRequestResource.class);

    @Inject
    AuthorizationService authorizationService;

    @GET
    public Response get(@Context HttpHeaders headers, @Context UriInfo uriInfo) {

        MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();

        AuthorizationRequestParameter requestParameter = new AuthorizationRequestParameter();
        requestParameter.responseType = queryParams.getFirst("response_type");
        requestParameter.state = queryParams.getFirst("state");
        requestParameter.scope = queryParams.getFirst("scope");
        requestParameter.redirectUri = queryParams.getFirst("redirect_uri");
        requestParameter.resource = queryParams.getFirst("resource");
        requestParameter.codeChallenge = queryParams.getFirst("code_challenge");
        requestParameter.codeChallengeMethod = queryParams.getFirst("code_challenge_method");
        requestParameter.requestedTokenType = queryParams.getFirst("requested_token_type");
        requestParameter.principal = queryParams.getFirst("principal");
        requestParameter.principalId = queryParams.getFirst("principal_id");
        requestParameter.group = queryParams.getFirst("group");
        requestParameter.groupId = queryParams.getFirst("group_id");
        requestParameter.personId = queryParams.getFirst("person_id");

        log2Console(headers, queryParams);

        if (!requestParameter.isComplete()) {
            LOG.error("Invalid request. At least one required parameter is missing.");
            return Response.status(400, "Invalid request. At least one required parameter is missing.").build();
        }

        // generate authorization code
        String code = UUID.randomUUID().toString();
        String uri = requestParameter.redirectUri + "?authorization_code=" + code + "&state=" + requestParameter.state;

        // register authorization request data at authorization service
        authorizationService.registerAuthorizationRequest(code, requestParameter);

        // re-direct to redirectUri. Uses http code 302 which allows the user agent to switch to the
        // http POST protocol to send the code and state to the applications callback endpoint.
        return Response.status(302).location(URI.create(uri)).build();
    }

    /**
     *
     */
    private static void log2Console(HttpHeaders headers, MultivaluedMap<String, String> queryParam) {

        LOG.info("Incoming request:");
        LOG.info("Header data:");

        MultivaluedMap<String, String> requestHeaders = headers.getRequestHeaders();
        requestHeaders.keySet().forEach(
                key -> LOG.info(key + ":" + requestHeaders.get(key))
        );

        LOG.info("Incoming request with query parameters:");
        queryParam.keySet().forEach(
                key -> LOG.info(key + ":" + queryParam.get(key))
        );
    }


}
