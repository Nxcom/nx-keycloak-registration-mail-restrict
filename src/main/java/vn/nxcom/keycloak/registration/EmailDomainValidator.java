package vn.nxcom.keycloak.registration;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;

public class EmailDomainValidator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Authenticator initialized!");
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No action logic for now
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        System.out.println("Authenticator closed!");
    }
}
