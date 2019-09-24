using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Blazor.Auth0.Models;
using Blazor.OpenId.Properties;
using Microsoft.AspNetCore.Http;

namespace Blazor.OpenId
{
    public class CommonAuthentication
    {

        /// <summary>
        /// Builds a log out URI.
        /// </summary>
        /// <param name="logoutendpoint">The OpenId logout endpoint</param>
        /// <param name="idToken">The OpenId id token.</param>
        /// <param name="redirectUri">The URI to redirect the user after the logout.</param>
        /// <returns>A <see cref="string"/> representing the log out url.</returns>
        public static string BuildLogoutUrl(Uri logoutendpoint, string idToken = null, string redirectUri = null)
        {
            if (logoutendpoint == null)
            {
                throw new ArgumentException(Resources.NullArgumentExceptionError, nameof(logoutendpoint));
            }
            var query = new QueryString();

            if (!string.IsNullOrEmpty(idToken))
            {
                query = query.Add("id_token_hint", idToken);
            }

            if (!string.IsNullOrEmpty(redirectUri))
            {
                query = query.Add("post_logout_redirect_uri", redirectUri);
            }

            var uri = new UriBuilder()
            {
                Scheme = logoutendpoint.Scheme,
                Host = logoutendpoint.Host,
                Path = logoutendpoint.PathAndQuery,
                Query = query.ToUriComponent(),
            };

            // TODO: Implement propper Uri creation
            return uri.Uri.AbsoluteUri;
        }
        /// <summary>
        /// Makes a call to the /userinfo endpoint and returns the user profile.
        /// </summary>
        /// <param name="httpClient">A <see cref="HttpClient"/> instance.</param>
        /// <param name="endpoint">The OpenId userinfo endpoint.</param>
        /// <param name="accessToken">The access_token received after the user authentication flow.</param>
        /// <returns>A <see cref="UserInfo"/>.</returns>
        public static async Task<UserInfo> UserInfo(HttpClient httpClient, string endpoint, string accessToken)
        {
            if (httpClient is null)
            {
                throw new ArgumentNullException(nameof(httpClient));
            }
            if (string.IsNullOrEmpty(endpoint))
            {
                throw new ArgumentException("Endpoint required");
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                throw new ArgumentException("accessToken required");
            }

            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            HttpResponseMessage response = await httpClient.GetAsync($@"{endpoint}").ConfigureAwait(false);

            var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return response.StatusCode == System.Net.HttpStatusCode.OK ? JsonSerializer.Deserialize<UserInfo>(responseText) : null;
        }
    }
}