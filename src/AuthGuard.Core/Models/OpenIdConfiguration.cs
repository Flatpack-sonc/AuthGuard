using System.Text.Json.Serialization;

namespace AuthGuard.Core.Models;

/// <summary>OIDC discovery document (OpenID Provider Metadata).</summary>
public sealed class OpenIdConfiguration
{
    [JsonPropertyName("issuer")]
    public string? Issuer { get; set; }

    [JsonPropertyName("authorization_endpoint")]
    public string? AuthorizationEndpoint { get; set; }

    [JsonPropertyName("token_endpoint")]
    public string? TokenEndpoint { get; set; }

    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; set; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; set; }

    [JsonPropertyName("registration_endpoint")]
    public string? RegistrationEndpoint { get; set; }

    [JsonPropertyName("scopes_supported")]
    public List<string>? ScopesSupported { get; set; }

    [JsonPropertyName("response_types_supported")]
    public List<string>? ResponseTypesSupported { get; set; }

    [JsonPropertyName("response_modes_supported")]
    public List<string>? ResponseModesSupported { get; set; }

    [JsonPropertyName("grant_types_supported")]
    public List<string>? GrantTypesSupported { get; set; }

    [JsonPropertyName("acr_values_supported")]
    public List<string>? AcrValuesSupported { get; set; }

    [JsonPropertyName("subject_types_supported")]
    public List<string>? SubjectTypesSupported { get; set; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<string>? IdTokenSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("id_token_encryption_alg_values_supported")]
    public List<string>? IdTokenEncryptionAlgValuesSupported { get; set; }

    [JsonPropertyName("id_token_encryption_enc_values_supported")]
    public List<string>? IdTokenEncryptionEncValuesSupported { get; set; }

    [JsonPropertyName("userinfo_signing_alg_values_supported")]
    public List<string>? UserInfoSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("request_object_signing_alg_values_supported")]
    public List<string>? RequestObjectSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public List<string>? TokenEndpointAuthMethodsSupported { get; set; }

    [JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")]
    public List<string>? TokenEndpointAuthSigningAlgValuesSupported { get; set; }

    [JsonPropertyName("display_values_supported")]
    public List<string>? DisplayValuesSupported { get; set; }

    [JsonPropertyName("claim_types_supported")]
    public List<string>? ClaimTypesSupported { get; set; }

    [JsonPropertyName("claims_supported")]
    public List<string>? ClaimsSupported { get; set; }

    [JsonPropertyName("service_documentation")]
    public string? ServiceDocumentation { get; set; }

    [JsonPropertyName("claims_locales_supported")]
    public List<string>? ClaimsLocalesSupported { get; set; }

    [JsonPropertyName("ui_locales_supported")]
    public List<string>? UiLocalesSupported { get; set; }

    [JsonPropertyName("claims_parameter_supported")]
    public bool? ClaimsParameterSupported { get; set; }

    [JsonPropertyName("request_parameter_supported")]
    public bool? RequestParameterSupported { get; set; }

    [JsonPropertyName("request_uri_parameter_supported")]
    public bool? RequestUriParameterSupported { get; set; }

    [JsonPropertyName("require_request_uri_registration")]
    public bool? RequireRequestUriRegistration { get; set; }

    [JsonPropertyName("op_policy_uri")]
    public string? OpPolicyUri { get; set; }

    [JsonPropertyName("op_tos_uri")]
    public string? OpTosUri { get; set; }

    [JsonPropertyName("code_challenge_methods_supported")]
    public List<string>? CodeChallengeMethodsSupported { get; set; }

    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; set; }

    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; set; }

    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; set; }

    [JsonPropertyName("check_session_iframe")]
    public string? CheckSessionIframe { get; set; }

    [JsonPropertyName("frontchannel_logout_supported")]
    public bool? FrontchannelLogoutSupported { get; set; }

    [JsonPropertyName("frontchannel_logout_session_supported")]
    public bool? FrontchannelLogoutSessionSupported { get; set; }

    [JsonPropertyName("backchannel_logout_supported")]
    public bool? BackchannelLogoutSupported { get; set; }

    [JsonPropertyName("backchannel_logout_session_supported")]
    public bool? BackchannelLogoutSessionSupported { get; set; }

    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    public bool? AuthorizationResponseIssParameterSupported { get; set; }

    [JsonPropertyName("device_authorization_endpoint")]
    public string? DeviceAuthorizationEndpoint { get; set; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public string? PushedAuthorizationRequestEndpoint { get; set; }

    [JsonPropertyName("require_pushed_authorization_requests")]
    public bool? RequirePushedAuthorizationRequests { get; set; }

    [JsonPropertyName("mtls_endpoint_aliases")]
    public Dictionary<string, string>? MtlsEndpointAliases { get; set; }

    [JsonPropertyName("tls_client_certificate_bound_access_tokens")]
    public bool? TlsClientCertificateBoundAccessTokens { get; set; }

    [JsonPropertyName("dpop_signing_alg_values_supported")]
    public List<string>? DpopSigningAlgValuesSupported { get; set; }

    /// <summary>Raw JSON for evidence / offline round-trips.</summary>
    [JsonIgnore]
    public string? RawJson { get; set; }
}
