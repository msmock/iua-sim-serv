package org.fnm;

import org.fnm.helper.GrantType;
import org.jboss.logging.Logger;

public class AuthorizationRequestParameter {

    private static final Logger LOG = Logger.getLogger(AuthorizationRequestParameter.class);

    public String grantType = GrantType.authorizationCode;

    // required
    public String responseType; // required shall be code
    public String state; // required csf token
    public String scope; // required scope
    public String redirectUri; // required url of the client

    //optional
    public String personId; // optional. Indicates the token as a basic or an extended token.
    public String resource; // optional resource server endpoint
    public String codeChallenge; // optional cryptographic challenge
    public String codeChallengeMethod; // optional cryptographic challenge method
    public String requestedTokenType; // optional token type

    // optional claims to responsible parties the user acts on behalf of
    public String principal;
    public String principalId;
    public String group;
    public String groupId;

    /**
     * @return true, if all required fields are set
     */
    public boolean isComplete() {
        return (grantType != null && !grantType.isEmpty() &&
                responseType != null && !responseType.isEmpty() &&
                state != null && !state.isEmpty() &&
                scope != null && !scope.isEmpty() &&
                redirectUri != null && !redirectUri.isEmpty()
        );
    }

    /**
     * indicates the token as a basic or an extended token.
     */
    public boolean isExtended(){
        return personId != null && !personId.isEmpty();
    }
}
