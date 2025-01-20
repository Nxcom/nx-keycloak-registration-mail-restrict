package vn.nxcom.keycloak.registration;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class EmailDomainValidator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Log the entry into the authenticate method
        System.out.println("EmailDomainValidator: authenticate() called");

        // Just for testing, log the user information
        UserModel user = context.getUser();
        if (user == null) {
            // If no user is found, log the error and return
            System.out.println("EmailDomainValidator: No user found!");
            context.failure(AuthenticationFlowError.INVALID_USER, Response.status(Response.Status.BAD_REQUEST).build());
            return;
        }

        // For now, just log the user's email
        String email = user.getEmail();
        System.out.println("EmailDomainValidator: User email: " + email);

        // Continue with success for testing
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Log the action method
        System.out.println("EmailDomainValidator: action() called");
    }

    @Override
    public boolean requiresUser() {
        // Log the decision about requiring a user
        System.out.println("EmailDomainValidator: requiresUser() called, returning false");
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Log whether the provider is configured for the user
        System.out.println("EmailDomainValidator: configuredFor() called, returning true");
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No actions required for testing
    }

    @Override
    public void close() {
        // Log the closing of the provider
        System.out.println("EmailDomainValidator: close() called");
    }

    // Factory to create instances of the EmailDomainValidator
    public static class Factory implements AuthenticatorFactory {

        @Override
        public Authenticator create(KeycloakSession session) {
            // Log factory creation
            System.out.println("EmailDomainValidator: Factory create() called");
            return new EmailDomainValidator();
        }

        @Override
        public String getId() {
            return "email-domain-validator";  // Identifier for this provider
        }

        @Override
        public String getDisplayType() {
            return "Email Domain Validator";  // Display name for this provider
        }

        @Override
        public String getHelpText() {
            return "Validates user email domains.";  // Description in the admin console
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            // Just log the configuration properties for now (not used in this simple test)
            System.out.println("EmailDomainValidator: getConfigProperties() called");
            return Arrays.asList(); // No config properties for testing
        }

        @Override
        public boolean isConfigurable() {
            return false;  // No configuration for now
        }

        @Override
        public void init(Config.Scope config) {
        }

        @Override
        public void postInit(KeycloakSessionFactory factory) {
        }

        @Override
        public void close() {
        }

        @Override
        public String getReferenceCategory() {
            return null;
        }

        @Override
        public boolean isUserSetupAllowed() {
            return false;
        }

        @Override
        public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
            return new AuthenticationExecutionModel.Requirement[0];
        }
    }
}
