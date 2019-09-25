using Blazor.Auth0;
using Blazor.Auth0.Models;
using Blazor.Auth0.Models.Enumerations;
using Blazor.OpenId.Models;
using Blazor.OpenId.Properties;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;
using System.Threading.Tasks;
using System.Timers;

namespace Blazor.OpenId
{
    public class AuthenticationService : IAuthenticationService, IDisposable
    {
        private readonly OpenidClientOptions clientOptions;
        private readonly NavigationManager navigationManager;
        private readonly HttpClient httpClient;
        private readonly IJSRuntime jsRuntime;

        private readonly ILogger logger;
        private readonly DotNetObjectReference<AuthenticationService> dotnetObjectRef;

        private SessionAuthorizationTransaction sessionAuthorizationTransaction;
        private Timer logOutTimer;
        private OpenId.Models.SessionStates sessionState = OpenId.Models.SessionStates.Undefined;

        /// <inheritdoc/>
        public event EventHandler<OpenId.Models.SessionStates> SessionStateChangedEvent;

        /// <inheritdoc/>
        public event Func<object, OpenId.Models.SessionStates, Task> SessionStateChangedEventAsync;

        /// <summary>
        /// The event fired just before staring a silent login.
        /// </summary>
        public event EventHandler<bool> BeforeSilentLoginEvent;

        /// <inheritdoc/>
        public UserInfo User { get; private set; }

        /// <inheritdoc/>
        public OpenId.Models.SessionStates SessionState
        {
            get => sessionState;
            private set  
            {
                if (value != sessionState)
                {
                    sessionState = value;
                    Task.Run(async () => await SessionStateChangedEventAsync?.Invoke(this, SessionState));
                    SessionStateChangedEvent?.Invoke(this, SessionState);
                }
            }
        }

        /// <inheritdoc/>
        public SessionInfo SessionInfo { get; private set; }

        private bool RequiresNonce => clientOptions.ResponseType == ResponseTypes.IdToken || clientOptions.ResponseType == ResponseTypes.TokenAndIdToken;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationService"/> class.
        /// </summary>
        /// <param name="logger">A <see cref="ILogger"/> param.</param>
        /// <param name="componentContext">A <see cref="IComponentContext"/> param.</param>
        /// <param name="httpClient">A <see cref="HttpClient"/> param.</param>
        /// <param name="jsRuntime">A <see cref="IJSRuntime"/> param.</param>
        /// <param name="navigationManager">A <see cref="NavigationManager"/> param.</param>
        /// <param name="options">A <see cref="ClientOptions"/> param.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("StyleCop.CSharp.OrderingRules", "SA1201:Elements should appear in the correct order", Justification = "I like this best ;)")]
        public AuthenticationService(ILogger<AuthenticationService> logger, HttpClient httpClient, IJSRuntime jsRuntime, NavigationManager navigationManager, OpenidClientOptions options)
        {
            this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
            this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            this.jsRuntime = jsRuntime ?? throw new ArgumentNullException(nameof(jsRuntime));
            this.navigationManager = navigationManager ?? throw new ArgumentNullException(nameof(navigationManager));
            clientOptions = options ?? throw new ArgumentNullException(nameof(options));
            sessionState = Models.SessionStates.NoConfig;
            Task.Run(async () => await ConfigureEndpoints(options).ConfigureAwait(false));
            dotnetObjectRef = DotNetObjectReference.Create(this);

            
        }

        /// <summary>
        /// Stops the next Silent Login iterarion.
        /// </summary>
        public void StopSilentLogin()
        {
            logOutTimer?.Stop();
        }

        /// <inheritdoc/>
        public async Task Authorize()
        {
            if (sessionState == Models.SessionStates.NoConfig) return;
            OpenId.Models.AuthorizeOptions options = BuildAuthorizeOptions();

            await Authentication.Authorize(jsRuntime, navigationManager, options).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public Task LogOut(string redirectUri = null)
        {
            var logoutUrl = CommonAuthentication.BuildLogoutUrl(clientOptions.EndSessionEndpoint, SessionInfo.IdToken);
            ClearSession();
            navigationManager.NavigateTo(logoutUrl);
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            GenericIdentity identity = null;

            switch (SessionState)
            {
                case OpenId.Models.SessionStates.Active:

                    identity = new GenericIdentity(User?.Name ?? string.Empty, "JWT");

                    if (!string.IsNullOrEmpty(User.Sub?.Trim()))
                    {
                        identity.AddClaim(new Claim("sub", User.Sub));
                    }

                    if (!string.IsNullOrEmpty(User.Name?.Trim()))
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Name, User.Name));
                    }

                    if (!string.IsNullOrEmpty(User.GivenName?.Trim()))
                    {
                        identity.AddClaim(new Claim("given_name", User.GivenName));
                    }

                    if (!string.IsNullOrEmpty(User.FamilyName?.Trim()))
                    {
                        identity.AddClaim(new Claim("family_name", User.FamilyName));
                    }

                    if (!string.IsNullOrEmpty(User.MiddleName?.Trim()))
                    {
                        identity.AddClaim(new Claim("middle_name", User.MiddleName));
                    }

                    if (!string.IsNullOrEmpty(User.Nickname?.Trim()))
                    {
                        identity.AddClaim(new Claim("nickname", User.Nickname));
                    }

                    if (!string.IsNullOrEmpty(User.PreferredUsername?.Trim()))
                    {
                        identity.AddClaim(new Claim("preferred_username", User.PreferredUsername));
                    }

                    if (!string.IsNullOrEmpty(User.Profile?.Trim()))
                    {
                        identity.AddClaim(new Claim("profile", User.Profile));
                    }

                    if (!string.IsNullOrEmpty(User.Picture?.Trim()))
                    {
                        identity.AddClaim(new Claim("picture", User.Picture));
                    }

                    if (!string.IsNullOrEmpty(User.Website?.Trim()))
                    {
                        identity.AddClaim(new Claim("website", User.Website));
                    }

                    if (!string.IsNullOrEmpty(User.Email?.Trim()))
                    {
                        identity.AddClaim(new Claim("email", User.Email));
                    }

                    identity.AddClaim(new Claim("email_verified", User.EmailVerified.ToString()));

                    if (!string.IsNullOrEmpty(User.Gender?.Trim()))
                    {
                        identity.AddClaim(new Claim("gender", User.Gender));
                    }

                    if (!string.IsNullOrEmpty(User.Birthdate?.Trim()))
                    {
                        identity.AddClaim(new Claim("birthdate", User.Birthdate));
                    }

                    if (!string.IsNullOrEmpty(User.Zoneinfo?.Trim()))
                    {
                        identity.AddClaim(new Claim("zoneinfo", User.Zoneinfo));
                    }

                    if (!string.IsNullOrEmpty(User.Locale?.Trim()))
                    {
                        identity.AddClaim(new Claim("locale", User.Locale));
                    }

                    if (!string.IsNullOrEmpty(User.PhoneNumber?.Trim()))
                    {
                        identity.AddClaim(new Claim("phone_number", User.PhoneNumber));
                    }

                    identity.AddClaim(new Claim("phone_number_verified", User.PhoneNumberVerified.ToString()));

                    if (!string.IsNullOrEmpty(User.Address?.Trim()))
                    {
                        identity.AddClaim(new Claim("address", User.Address));
                    }

                    identity.AddClaim(new Claim("updated_at", User.UpdatedAt.ToString()));

                    identity.AddClaims(User.CustomClaims.Select(customClaim => new Claim(customClaim.Key, customClaim.Value.GetRawText(), customClaim.Value.ValueKind.ToString())));
                    identity.AddClaims(User.CustomClaims.Select(customClaim => new Claim(customClaim.Key, customClaim.Value.GetRawText(), customClaim.Value.ValueKind.ToString())));

                    identity.AddClaims(User.Permissions.Select(permission => new Claim($"{permission}", "true", "permissions")));

                    break;
                case OpenId.Models.SessionStates.Undefined:
                case OpenId.Models.SessionStates.Inactive:
                case OpenId.Models.SessionStates.NoConfig:
                    identity = new GenericIdentity(string.Empty, "JWT");

                    break;
            }

            return Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identity)));
        }
        /// <inheritdoc/>
        public async Task ValidateSession()
        {
            ValidateSession(navigationManager.Uri);
        }
       
        private async Task ValidateSession(string uri)
        {
            // Let's validate the hash
            Uri absoluteUri = navigationManager.ToAbsoluteUri(uri);
            
            ParsedHash parsedHash = Authentication.ParseHash(new ParseHashOptions
            {
                ResponseType = clientOptions.ResponseType,
                AbsoluteUri = absoluteUri,
            });

            // No hash found?!
            if (parsedHash == null)
            {
                // Should we keep the session alive?
                if ((clientOptions.SlidingExpiration && sessionState == OpenId.Models.SessionStates.Active) || clientOptions.RequireAuthenticatedUser)
                {
                    await SilentLogin().ConfigureAwait(false);
                }
                else
                {
                    if (sessionState == OpenId.Models.SessionStates.Active)
                    {
                        await LogOut().ConfigureAwait(false);
                    }
                    SessionState = OpenId.Models.SessionStates.Inactive;
                    ClearSession();
                }
            }
            else
            {

                // We have a valid hash parameter collection, let's validate the authorization response
                await HandleAuthorizationResponseAsync(new AuthorizationResponse
                {
                    AccessToken = parsedHash.AccessToken,
                    Code = parsedHash.Code,
                    Error = parsedHash.Error,
                    ErrorDescription = parsedHash.ErrorDescription,
                    ExpiresIn = 15,
                    IdToken = parsedHash.IdToken,
                    IsTrusted = false,
                    Origin = absoluteUri.Authority,
                    Scope = string.Empty,
                    State = parsedHash.State,
                    TokenType = "bearer", // TODO: Improve this validation
                    Type = nameof(ResponseModes.Query), // TODO: Improve this validation
                }).ConfigureAwait(false);
            }
        }
        
        /// <inheritdoc/>
        [JSInvokable]
        /// <summary>
        /// Meant for internal API use only.
        /// </summary>
        public async Task HandleAuthorizationResponseAsync(AuthorizationResponse authorizationResponse)
        {
            try
            {
                sessionAuthorizationTransaction = await TransactionManager.GetStoredTransactionAsync(jsRuntime, clientOptions, authorizationResponse.State).ConfigureAwait(false);

                Authentication.ValidateAuthorizationResponse(authorizationResponse, clientOptions.Domain, sessionAuthorizationTransaction?.State);

                SessionInfo tempSessionInfo = await GetSessionInfoAsync(authorizationResponse).ConfigureAwait(false);

                UserInfo tempIdTokenInfo = await GetUserAsync(tempSessionInfo.AccessToken, tempSessionInfo.IdToken).ConfigureAwait(false);

                ValidateIdToken(tempIdTokenInfo, authorizationResponse.AccessToken);

                InitiateUserSession(tempIdTokenInfo, tempSessionInfo);

                ScheduleLogOut();
            }
            catch (ApplicationException ex)
            {
                Console.WriteLine("Error:");

                await OnLoginRequestValidationError(authorizationResponse.Error, ex.Message).ConfigureAwait(false);
            }
            finally
            {
                RedirectToHome();
            }
        }

        /// <inheritdoc/>
        [JSInvokable]
        /// <summary>
        /// Meant for internal API use only.
        /// </summary>
        public async Task HandleAuthorizationFromIframeQuery(string authorizationResponse)
        {
            await ValidateSession(authorizationResponse);   
        }
        private void RedirectToHome()
        {
            var abosulteUri = new Uri(navigationManager.Uri);

            sessionAuthorizationTransaction = null;

            // Redirect to home (removing the hash)
            navigationManager.NavigateTo(abosulteUri.GetLeftPart(UriPartial.Path));
        }

        private async Task<SessionInfo> GetSessionInfoAsync(AuthorizationResponse authorizationResponse)
        {
            if (authorizationResponse is null)
            {
                throw new ArgumentNullException(nameof(authorizationResponse));
            }

            return clientOptions.ResponseType == ResponseTypes.Code
                ? await GetSessionInfoAsync(authorizationResponse.Code).ConfigureAwait(false)
                : new SessionInfo()
                    {
                        AccessToken = authorizationResponse.AccessToken,
                        ExpiresIn = authorizationResponse.ExpiresIn,
                        IdToken = authorizationResponse.IdToken,
                        Scope = authorizationResponse.Scope,
                        TokenType = authorizationResponse.TokenType,
                    };
        }

        private async Task<SessionInfo> GetSessionInfoAsync(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                throw new ArgumentException(Resources.NullArgumentExceptionError, nameof(code));
            }

            return await Authentication.GetAccessToken(
                    httpClient,
                    clientOptions.TokenEndpoint.AbsoluteUri,
                    clientOptions.ClientId,
                    code,
                    audience: clientOptions.Audience,
                    codeVerifier: sessionAuthorizationTransaction?.CodeVerifier,
                    secret: clientOptions.ClientSecret,
                    redirectUri: sessionAuthorizationTransaction?.RedirectUri,
                    requestMode: clientOptions.RequestMode)
                .ConfigureAwait(false);
        }

        private async Task<UserInfo> GetUserAsync(string accessToken, string idToken = null)
        {
            if (!string.IsNullOrEmpty(idToken) && (RequiresNonce || clientOptions.GetUserInfoFromIdToken))
            {
                return Auth0.CommonAuthentication.DecodeTokenPayload<UserInfo>(idToken);
            }
            else
            {
                // In case we're not getting the id_token from the message response or GetUserInfoFromIdToken is set to false try to get it from Auth0's API
                return await CommonAuthentication.UserInfo(httpClient, clientOptions.UserInfoEndpoint.AbsoluteUri, accessToken).ConfigureAwait(false);
            }
        }

        private void ValidateIdToken(UserInfo idTokenInfo, string accessToken)
        {
            if (RequiresNonce)
            {
                var nonceIsValid = idTokenInfo?.Nonce.Replace(' ', '+').Equals(sessionAuthorizationTransaction?.Nonce.Replace(' ', '+'));

                if (nonceIsValid.HasValue && !nonceIsValid.Value)
                {
                    throw new ApplicationException(Resources.InvalidNonceError);
                }

                if (string.IsNullOrEmpty(idTokenInfo.AtHash))
                {
                    Console.WriteLine(Resources.NotAltChashWarning);
                }
                else
                {
                    var atHashIsValid = Authentication.ValidateAccessTokenHash(idTokenInfo.AtHash, accessToken);

                    if (!atHashIsValid)
                    {
                        throw new ApplicationException(Resources.InvalidAccessTokenHashError);
                    }
                }
            }
        }

        private void InitiateUserSession(UserInfo userInfo, SessionInfo sessionInfo)
        {
            if (!string.IsNullOrEmpty(clientOptions.Audience) && !string.IsNullOrEmpty(sessionInfo.AccessToken))
            {
                try
                {
                    List<string> permissionsList = Auth0.CommonAuthentication.DecodeTokenPayload<AccessTokenPayload>(sessionInfo.AccessToken).Permissions ?? new List<string>();
                    userInfo.Permissions.AddRange(permissionsList);
                }
                catch
                {
                    List<string> permissionsList = Auth0.CommonAuthentication.DecodeTokenPayload<AccessTokenPayloadStringAud>(sessionInfo.AccessToken).Permissions ?? new List<string>();
                    userInfo.Permissions.AddRange(permissionsList);
                }
            }

            User = userInfo;

            SessionInfo = sessionInfo;

            SessionState = OpenId.Models.SessionStates.Active;
        }

        private async Task OnLoginRequestValidationError(string error, string validationMessage)
        {
            // In case of any error negate the access
            if (!string.IsNullOrEmpty(validationMessage))
            {
                ClearSession();

                Console.WriteLine("Login Error: " + validationMessage);

                if (error.ToLower() == "login_required" && clientOptions.RequireAuthenticatedUser)
                {
                    await Authorize().ConfigureAwait(false);
                    System.Threading.Thread.Sleep(30000);
                    navigationManager.NavigateTo("/");
                }
            }
        }

        private OpenId.Models.AuthorizeOptions BuildAuthorizeOptions()
        {
            var isUsingSecret = !string.IsNullOrEmpty(clientOptions.ClientSecret);
            ResponseTypes responseType = isUsingSecret ? ResponseTypes.Code : clientOptions.ResponseType;
            ResponseModes responseMode = isUsingSecret ? ResponseModes.Query : clientOptions.ResponseMode;
            CodeChallengeMethods codeChallengeMethod = !isUsingSecret && responseType == ResponseTypes.Code ? CodeChallengeMethods.S256 : CodeChallengeMethods.None;
            var codeVerifier = codeChallengeMethod != CodeChallengeMethods.None ? Auth0.CommonAuthentication.GenerateNonce(clientOptions.KeyLength) : null;
            var codeChallenge = codeChallengeMethod != CodeChallengeMethods.None ? Utils.GetSha256(codeVerifier) : null;
            var nonce = Auth0.CommonAuthentication.GenerateNonce(clientOptions.KeyLength);

            return new OpenId.Models.AuthorizeOptions
            {
                Audience = clientOptions.Audience,
                ClientID = clientOptions.ClientId,
                AuthorizeEndpoint = clientOptions.AuthorizeEndpoint,
                CodeChallengeMethod = codeChallengeMethod,
                CodeVerifier = codeVerifier,
                CodeChallenge = codeChallenge,
                Connection = clientOptions.Connection,
                Domain = clientOptions.Domain,
                Nonce = nonce,
                Realm = clientOptions.Realm,
                RedirectUri = BuildRedirectUrl(),
                ResponseMode = responseMode,
                ResponseType = responseType,
                Scope = clientOptions.Scope,
                State = Auth0.CommonAuthentication.GenerateNonce(clientOptions.KeyLength),
                Namespace = clientOptions.Namespace,
                KeyLength = clientOptions.KeyLength,
            };
        }

        private void ClearSession()
        {
            SessionState = clientOptions.RequireAuthenticatedUser ? OpenId.Models.SessionStates.Undefined : OpenId.Models.SessionStates.Inactive;
            User = null;
            SessionInfo = null;
            sessionAuthorizationTransaction = null;
            logOutTimer?.Stop();
            logOutTimer?.Dispose();
        }

        public async Task SilentLogin()
        {

            BeforeSilentLoginEvent?.Invoke(this, false);

            OpenId.Models.AuthorizeOptions options = BuildAuthorizeOptions();
            options.ResponseMode = ResponseModes.Query;

            options = await TransactionManager.Proccess(jsRuntime, options).ConfigureAwait(false);

            var authorizeUrl = Authentication.BuildAuthorizeUrl(options);

            await jsRuntime.InvokeAsync<object>($"{Resources.InteropElementName}.drawIframe", dotnetObjectRef, $"{authorizeUrl}&prompt=none").ConfigureAwait(false);
        }

        private void ScheduleLogOut()
        {
            logOutTimer?.Stop();

            if (logOutTimer == null)
            {
                logOutTimer = new Timer();
                logOutTimer.Elapsed += async (object source, ElapsedEventArgs e) =>
                {
                    logOutTimer.Stop();

                    if (clientOptions.SlidingExpiration)
                    {
                        await SilentLogin().ConfigureAwait(false);
                        return;
                    }

                    await LogOut().ConfigureAwait(false);

                    ClearSession();
                };
            }

            logOutTimer.Interval = (SessionInfo.ExpiresIn - 5) * 1000;

            logOutTimer.Start();
        }
        private async Task ConfigureEndpoints(OpenidClientOptions clientOptions)
        {
            OpenidConfiguration response = null;
            var found = false;
            var protocall = clientOptions.UseHttpEndpoints ? "http" : "https";
            using (var httpClient = new HttpClient())
            {
                HttpResponseMessage httpResponseMessage = await httpClient.GetAsync($@"{protocall}://{clientOptions.Domain}/.well-known/openid-configuration").ConfigureAwait(false);
                var responseText = await httpResponseMessage.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (httpResponseMessage.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    found = true;
                    response = JsonSerializer.Deserialize<OpenidConfiguration>(responseText);
                }
               
            }
            if (!found)
            {
                clientOptions.AuthorizeEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/authorize");
                clientOptions.TokenEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/token");
                clientOptions.UserInfoEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/userinfo");
                clientOptions.DeviceAuthorizationEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/deviceauthorization");
                clientOptions.IntrospectionEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/introspect");
                clientOptions.RevocationEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/revoke");
                clientOptions.EndSessionEndpoint = new Uri($@"{protocall}://{clientOptions.Domain}/oauth/endsession");
            }
            clientOptions.AuthorizeEndpoint = response.AuthorizationEndpoint;
            clientOptions.TokenEndpoint = response.TokenEndpoint;
            clientOptions.UserInfoEndpoint = response.UserinfoEndpoint;
            clientOptions.DeviceAuthorizationEndpoint = response.DeviceAuthorizationEndpoint;
            clientOptions.IntrospectionEndpoint = response.IntrospectionEndpoint;
            clientOptions.RevocationEndpoint = response.RevocationEndpoint;
            clientOptions.EndSessionEndpoint = response.EndSessionEndpoint;

            SessionState = OpenId.Models.SessionStates.Processing;
            await ValidateSession().ConfigureAwait(false);
        }
        private string BuildRedirectUrl()
        {
            var abosulteUri = new Uri(navigationManager.Uri);
            var uri = !string.IsNullOrEmpty(clientOptions.RedirectUri) ? clientOptions.RedirectUri : clientOptions.RedirectAlwaysToHome ? abosulteUri.GetLeftPart(UriPartial.Authority) : abosulteUri.AbsoluteUri;

            return !string.IsNullOrEmpty(clientOptions.RedirectUri) && !clientOptions.RedirectAlwaysToHome ? clientOptions.RedirectUri : uri;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).

                    dotnetObjectRef.Dispose();
                    httpClient.Dispose();
                    ((IDisposable)logOutTimer)?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AuthenticationService()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.

        /// <inheritdoc/>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);

            // TODO: uncomment the following line if the finalizer is overridden above.
            GC.SuppressFinalize(this);
        }

       
        #endregion

    }

}
