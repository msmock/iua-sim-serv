package org.fnm;

public class RequestParameter {

    private String grantType;
    private String clientId;
    private String clientSecret;
    private String principal;
    private String principalId;
    private String scope;
    private String personId;

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

    /**
     * @return true, if personId is set indicating a extended token
     */
    public boolean isBasic(){
        return personId != null && isComplete();
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getPrincipalId() {
        return principalId;
    }

    public void setPrincipalId(String principalId) {
        this.principalId = principalId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getPersonId() {
        return personId;
    }

    public void setPersonId(String personId) {
        this.personId = personId;
    }

}
