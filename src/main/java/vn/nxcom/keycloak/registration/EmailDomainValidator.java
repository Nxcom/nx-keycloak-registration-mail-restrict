package net.micedre.keycloak.registration;

import java.util.ArrayList;
import java.util.List;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

public class RegistrationProfileWithMailDomainCheck implements FormAction, FormActionFactory {

    public static final String PROVIDER_ID = "registration-mail-check-action";

    @Override
    public String getDisplayType() {
        return "Profile Validation with email domain check";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Adds validation of domain emails for registration";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("validDomains");
        property.setLabel("Valid domains for emails");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        property.setHelpText("List of email domains authorized to register, separated by '##'.");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        List<FormMessage> errors = new ArrayList<>();
        String email = formData.getFirst(Validation.FIELD_EMAIL);

        boolean emailDomainValid = false;
        AuthenticatorConfigModel mailDomainConfig = context.getAuthenticatorConfig();
        String eventError = Errors.INVALID_REGISTRATION;

        if (mailDomainConfig != null) {
            String validDomainsConfig = mailDomainConfig.getConfig().get("validDomains");
            if (validDomainsConfig != null && !validDomainsConfig.isEmpty()) {
                String[] domains = validDomainsConfig.split("##");
                for (String domain : domains) {
                    if (email != null && email.endsWith("@" + domain.trim())) {
                        emailDomainValid = true;
                        break;
                    }
                }
            }
        }

        if (!emailDomainValid) {
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(Validation.FIELD_EMAIL, Messages.INVALID_EMAIL));
        }

        if (!errors.isEmpty()) {
            context.error(eventError);
            context.validationError(formData, errors);
        } else {
            context.success();
        }
    }

    @Override
    public void buildPage(FormActionContext context, MultivaluedMap<String, String> formData) {
        // No additional page rendering needed
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
        // No resources to close
    }
} 
