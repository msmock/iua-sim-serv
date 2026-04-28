package org.fnm;

public class TokenRequestParameter {

    public String grantType;
    public String clientId;
    public String clientSecret;
    public String principal;
    public String principalId;
    public String scope;
    public String personId;

    /**
     * @return true, if personId is set indicating a extended token
     */
    public boolean isBasic(){
        return personId != null && isComplete();
    }

    /**
     * @return true, if all required fields are set
     */
    public boolean isComplete() {
        return (grantType != null && !grantType.isEmpty() &&
                clientId != null && !clientId.isEmpty() &&
                clientSecret != null && !clientSecret.isEmpty() &&
                principal != null && !principal.isEmpty() &&
                principalId != null && !principalId.isEmpty() &&
                scope != null && !scope.isEmpty()
        );
    }
}
