package org.fnm;

public class TokenRequestParameter {

    // common
    public String grantType;
    public String clientId;
    public String clientSecret;

    // CC Flow
    public String principal;
    public String principalId;
    public String scope;
    public String personId;

    // AC Flow
    public String code;
    public String clientAssertion;
    public String clientAssertionType;

    /**
     * @return true, if personId is set indicating a extended token
     */
    public boolean isBasic(){
        return isComplete() && personId == null;
    }

    /**
     * @return true, if all required fields are set
     */
    public boolean isComplete() {

        if (grantType == null || grantType.isEmpty()) {
            return false;
        }

        if (grantType.equals("client_credentials")) {
            return (clientId != null && !clientId.isEmpty() &&
                    clientSecret != null && !clientSecret.isEmpty() &&
                    principal != null && !principal.isEmpty() &&
                    principalId != null && !principalId.isEmpty() &&
                    scope != null && !scope.isEmpty());
        }

        if (grantType.equals("authorization_code")) {
            return (clientId != null && !clientId.isEmpty() &&
                    clientSecret != null && !clientSecret.isEmpty() &&
                    code != null && !code.isEmpty() &&
                    clientAssertion != null && !clientAssertion.isEmpty() &&
                    clientAssertionType != null && !clientAssertionType.isEmpty());
        }

        return false;
    }
}
