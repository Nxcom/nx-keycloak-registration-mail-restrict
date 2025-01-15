package vn.nxcom.keycloak.registration;

import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.AuthenticationExecutionRequirement;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class EmailDomainValidator implements Authenticator {

    private static final String ALLOWED_DOMAINS_KEY = "allowedDomains";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.INVALID_USER, Response.status(Response.Status.BAD_REQUEST).build());
            return;
        }

        String email = user.getEmail();
        if (email == null || email.isEmpty()) {
            context.getEvent().detail(Details.REASON, "Email is required");
            context.failure(AuthenticationFlowError.INVALID_USER, Response.status(Response.Status.BAD_REQUEST).entity("Email is required").build());
            return;
        }

        // Extract domain from the user's email
        String domain = email.split("@")[1];

        // Get allowed domains from configuration
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || !config.getConfig().containsKey(ALLOWED_DOMAINS_KEY)) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Configuration missing").build());
            return;
        }

        String allowedDomainsConfig = config.getConfig().get(ALLOWED_DOMAINS_KEY);
        Set<String> allowedDomains = Arrays.stream(allowedDomainsConfig.split(","))
                                           .map(String::trim)
                                           .collect(Collectors.toSet());

        // Validate the email domain
        if (!allowedDomains.contains(domain)) {
            context.failure(AuthenticationFlowError.INVALID_USER, Response.status(Response.Status.BAD_REQUEST).entity("Invalid email domain").build());
            return;
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    public static class Factory implements AuthenticatorFactory {

        @Override
        public Authenticator create(KeycloakSession session) {
            return new EmailDomainValidator();
        }

        @Override
        public String getId() {
            return "email-domain-validator";
        }

        @Override
        public String getDisplayType() {
            return "Email Domain Validator";
        }

        @Override
        public String getHelpText() {
            return "Validates user email domains.";
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            ProviderConfigProperty allowedDomainsProp = new ProviderConfigProperty();
            allowedDomainsProp.setName(ALLOWED_DOMAINS_KEY);
            allowedDomainsProp.setLabel("Allowed Email Domains");
            allowedDomainsProp.setHelpText("Comma-separated list of allowed email domains (e.g., company.com, example.org).");
            allowedDomainsProp.setType(ProviderConfigProperty.STRING_TYPE);
            allowedDomainsProp.setDefaultValue("company.com,example.org");

            return Arrays.asList(allowedDomainsProp);
        }

        @Override
        public boolean isConfigurable() {
            return true;
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
            return REQUIREMENT_CHOICES;
        }
    }
}
