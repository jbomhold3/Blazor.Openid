using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Blazor.OpenId
{
    public class AuthenticationStateProvider : Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider
    {
        private readonly IAuthenticationService authenticationService;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationStateProvider"/> class.
        /// </summary>
        /// <param name="authenticationService">A <see cref="IAuthenticationService"/> instance.</param>
        public AuthenticationStateProvider(IAuthenticationService authenticationService)
        {
            this.authenticationService = authenticationService ?? throw new ArgumentNullException(nameof(authenticationService));

            this.authenticationService.SessionStateChangedEvent += (a, b) =>
            {
                this.NotifyAuthenticationStateChanged(this.GetAuthenticationStateAsync());
            };
        }

        /// <inheritdoc/>
        public override Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            return this.authenticationService.GetAuthenticationStateAsync();
        }
    }
}
