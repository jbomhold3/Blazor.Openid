using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace Blazor.OpenId.Models
{
    /// <summary>
    /// Class representing the payload of an access token.
    /// </summary>
    public class AccessTokenPayloadStringAud
    {
        /// <summary>
        /// Gets or sets the permissions claims.
        /// </summary>
        [JsonPropertyName("permissions")]
        public List<string> Permissions { get; set; }

        /// <summary>
        /// Gets or sets the expedition time claim.
        /// </summary>
        [JsonPropertyName("iat")]
        public long Iat { get; set; }

        /// <summary>
        /// Gets or sets the expiration time claim.
        /// </summary>
        [JsonPropertyName("exp")]
        public long Exp { get; set; }

        /// <summary>
        /// Gets or sets the issuer claim.
        /// </summary>
        [JsonPropertyName("iss")]
        public string Iss { get; set; }

        /// <summary>
        /// Gets or sets the audiences claim.
        /// </summary>
        [JsonPropertyName("aud")]
        public string Aud { get; set; }

        /// <summary>
        /// Gets or sets the authorized party claim.
        /// </summary>
        [JsonPropertyName("azp")]
        public string Azp { get; set; }

        /// <summary>
        /// Gets or sets the scope party claim.
        /// </summary>
        [JsonPropertyName("scope")]
        public List<string> Scope { get; set; }
    }
}
