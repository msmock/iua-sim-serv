package org.fnm;

public class AuthorizationRequestParameter {

    public String grantType = "authorization_code";

    // required
    public String responseType; // required shall be code
    public String state; // required csf token
    public String scope; // required scope
    public String redirectUri; // required url of the client

    // optional
    public String resource; // optional resource server endpoint
    public String codeChallenge; // optional cryptographic challenge
    public String codeChallengeMethod; // optional cryptographic challenge method
    public String requestedTokenType; // optional token type

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
}
