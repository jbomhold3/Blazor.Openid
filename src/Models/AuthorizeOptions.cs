using Blazor.Auth0.Models;
using Blazor.Auth0.Models.Enumerations;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Blazor.OpenId.Models
{
    /// <summary>
    /// Class for handling the options required in the authentication flow.
    /// </summary>
    public class AuthorizeOptions : IValidatableObject
    {
        /// <summary>
        /// Gets or sets the Auth0's tenant domain used in the authentication flow.
        /// </summary>
        [Required(ErrorMessage = "{0} option is required")]
        public string Domain { get; set; }

        /// <summary>
        /// Gets or sets the Authorize Endpoint.
        /// </summary>
        public Uri AuthorizeEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the Auth0's tenant client id used in the authentication flow.
        /// </summary>
        [Required(ErrorMessage = "{0} option is required")]
        public string ClientID { get; set; }

        /// <summary>
        /// Gets or sets the URL to redirect the user after the user authentication.
        /// </summary>
        [Required(ErrorMessage = "{0} option is required")]
        public string RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="ResponseType"/> used in the authentication flow.
        /// </summary>
        [Required(ErrorMessage = "{0} option is required")]
        public ResponseTypes ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="ResponseModes"/> used in the authentication flow.
        /// </summary>
        public ResponseModes ResponseMode { get; set; }

        /// <summary>
        /// Gets or sets the state used in the authentication flow.
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// Gets or sets the nonce used in the authentication flow.
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="CodeChallengeMethods"/> used in the authentication flow.
        /// </summary>
        public CodeChallengeMethods CodeChallengeMethod { get; set; }

        /// <summary>
        /// Gets or sets the PKCE code challenge used in the authentication flow.
        /// </summary>
        public string CodeChallenge { get; set; }

        /// <summary>
        /// Gets or sets the PKCE code verifier used in the authentication flow.
        /// </summary>
        public string CodeVerifier { get; set; }

        /// <summary>
        /// Gets or sets the scope used in the authentication flow.
        /// </summary>
        [Required(ErrorMessage = "{0} option is required")]
        public string Scope { get; set; } = "openid profile email";

        /// <summary>
        /// Gets or sets the Auth0's Audience/API identifier used in the authentication flow.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the Auth0's connection used in the authentication flow.
        /// </summary>
        public string Connection { get; set; }

        /// <summary>
        /// Gets or sets the Auth0's realm used in the authentication flow.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the app state used in the authentication flow.
        /// </summary>
        public string AppState { get; set; }

        /// <summary>
        /// Gets or sets the namespace state used in the authentication flow.
        /// </summary>
        public object Namespace { get; set; }

        /// <summary>
        /// Gets or sets the length for the nonce and code callenges.
        /// </summary>
        public int KeyLength { get; set; }

        /// <inheritdoc/>
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var results = new List<ValidationResult>
            {
                ScopeValidation.ScopeValidate(Scope),
            };

            if (CodeChallengeMethod != CodeChallengeMethods.None && string.IsNullOrEmpty(CodeChallenge))
            {
                results.Add(new ValidationResult($"{nameof(CodeChallenge)} is not valid: You're using code_challenge_method='{Auth0.CommonAuthentication.ParseCodeChallengeMethod(CodeChallengeMethod)}' but no code_challenge is present"));
            }

            if (CodeChallengeMethod != CodeChallengeMethods.None && string.IsNullOrEmpty(CodeVerifier))
            {
                results.Add(new ValidationResult($"{nameof(CodeVerifier)} is not valid: You're using code_challenge_method='{Auth0.CommonAuthentication.ParseCodeChallengeMethod(CodeChallengeMethod)}' but no code_verifier is present"));
            }

            if (ResponseType == ResponseTypes.IdToken && ResponseType == ResponseTypes.TokenAndIdToken && string.IsNullOrEmpty(Nonce))
            {
                results.Add(new ValidationResult($"{nameof(Nonce)} is not valid: Nonce is required when using Implicit Grant (id_token or token id_token response types)"));
            }

            return results;
        }
    }
}
