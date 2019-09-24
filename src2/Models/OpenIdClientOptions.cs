using System;

namespace Blazor.OpenId.Models
{
    public class OpenidClientOptions : Auth0.Models.ClientOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether or not http endpoints should be used. This should only be enabled in devlopment.
        /// </summary>
        public bool UseHttpEndpoints { get; set; } 
        /// <summary>
        /// Gets or sets the Authorize Endpoint.
        /// </summary>
        public Uri AuthorizeEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the Token Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration.
        /// </summary>
        public Uri TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the UserInfo Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration.
        /// </summary>
        public Uri UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the Device Authorization Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration.
        /// /// Currently not used.
        /// </summary>
        public Uri DeviceAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the Introspection Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration.
        /// Currently not used.
        /// </summary>
        public Uri IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets Revocation Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration./// 
        /// </summary>
        public Uri RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets End Session Endpoint.
        /// Do not configure if your Auth server has a .well-known/openid-configuration.
        /// Currently not used.
        /// </summary>
        public Uri EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets row the Auth request is encoded  Supported values are `json`, and `form_post`.
        /// </summary>
        public RequestModes RequestMode { get; set; } = RequestModes.Json;
    }
}
