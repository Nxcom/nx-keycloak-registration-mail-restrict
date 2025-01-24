package vn.nxcom.keycloak;

import java.util.ArrayList;
import java.util.List;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import com.google.auto.service.AutoService;
import java.util.Arrays;

// Annotation to auto-register the provider
@AutoService({FormAction.class, FormActionFactory.class})
public class RegistrationProfileWithMailDomainCheck implements FormAction, FormActionFactory {

    public static final String PROVIDER_ID = "registration-mail-check-action";
    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Profile Validation with Email Domain Check";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }
    @Override
    public String getHelpText() {
        return "Adds validation of email domains during registration.";
    }

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName("validDomains");
        property.setLabel("Valid Domains for Emails");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        property.setHelpText("List of email domains authorized for registration.");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String email = formData.getFirst(Validation.FIELD_EMAIL);

        if (email == null || email.trim().isEmpty()) {
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, List.of(new FormMessage(Validation.FIELD_EMAIL, Messages.MISSING_EMAIL)));
            return;
        }

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        // Lấy danh sách từ config, cách nhau bởi dấu phảy. Nếu không có gì trong config thì mặc định là example.org (dummy)
        String[] validDomains = config.getConfig().getOrDefault("validDomains", "example.org").split("##");
        validDomains = Arrays.stream(validDomains)  // Convert to Stream for processing
                            .map(String::trim)  // Trim each domain
                            .toArray(String[]::new);  // Convert back to array

        boolean isValid = false;
        for (String domain : validDomains) {
            if (email.trim().endsWith(domain.trim())) {
                isValid = true;
                break;
            }
        }

        if (!isValid) {
            context.getEvent().detail(Details.EMAIL, email);
            context.error(Errors.INVALID_REGISTRATION);
            String allowedDomains = String.join(", ", validDomains);
            String errorMessage = "Your email is not in allowed domains: " + allowedDomains + "<br>Please use a valid one, or contact IT support for adding your domain if you think it should be added!";
            context.validationError(formData, List.of(new FormMessage(Validation.FIELD_EMAIL, errorMessage)));
        } else {
            context.success();
        }
    }


    @Override
    public void success(FormContext context) {
        // No additional actions needed on successful validation.
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions are needed for users after registration.
    }

    @Override
    public boolean requiresUser() {
        return false; // This action does not require a pre-existing user.
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true; // Always configured, as no special configuration is needed.
    }

    @Override
    public void close() {
        // No resources to clean up in this implementation.
    }

    // Factory Methods
    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }
}
