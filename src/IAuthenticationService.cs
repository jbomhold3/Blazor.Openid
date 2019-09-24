using Blazor.Auth0.Models;
using Blazor.OpenId.Models;
using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Blazor.OpenId
{
    /// <summary>
    /// Service for handling the authentication flow.
    /// </summary>
    public interface IAuthenticationService
    {
        Task SilentLogin();
        /// <summary>
        /// The event fired just after the session state has changed.
        /// </summary>
        event EventHandler<SessionStates> SessionStateChangedEvent;

        /// <summary>
        /// Gets a <see cref="SessionInfo"/> representing the current session.
        /// </summary>
        SessionInfo SessionInfo { get; }

        /// <summary>
        /// Gets a <see cref="SessionStates"/> representing the current session state Undefined, Active or Inactive.
        /// </summary>
        SessionStates SessionState { get; }

        /// <summary>
        /// Gets a <see cref="UserInfo"/> representing the current user.
        /// </summary>
        UserInfo User { get; }

        /// <summary>
        /// Initiates the Authorization flow by calling the IDP's /authorize enpoint.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the result of the asynchronous operation.</returns>
        Task Authorize();

        /// <summary>
        /// Gets the <see cref="AuthenticationState"/>.
        /// </summary>
        /// <returns>A <see cref="Task{TResult}"/> representing the result of the asynchronous operation.</returns>
        Task<AuthenticationState> GetAuthenticationStateAsync();

        /// <summary>
        /// Handles the <see cref="AuthenticationResponse"/>.
        /// </summary>
        /// <param name="authorizationResponse">The <see cref="AuthenticationResponse"/> param.</param>
        /// <returns>A <see cref="Task"/> representing the result of the asynchronous operation.</returns>
        Task HandleAuthorizationResponseAsync(AuthorizationResponse authorizationResponse);

        /// <summary>
        /// Initiates the Log Out flow by calling the IDP's /v2/logout endpoint.
        /// </summary>
        /// <param name="redirectUri">URL to redirect the user after the logout.</param>
        /// <returns>A <see cref="Task"/> representing the result of the asynchronous operation.</returns>
        Task LogOut(string redirectUri = null);

        /// <summary>
        /// Validates the current session status.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the result of the asynchronous operation.</returns>
        Task ValidateSession();
    }
}
