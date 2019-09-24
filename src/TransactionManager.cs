﻿using Blazor.Auth0;
using Blazor.Auth0.Models;
using Blazor.Auth0.Models.Enumerations;
using Blazor.OpenId.Models;
using Microsoft.JSInterop;
using System;
using System.Threading.Tasks;

namespace Blazor.OpenId
{
    /// <summary>
    /// Authentication flow trasanction manager class.
    /// </summary>
    public static class TransactionManager
    {
        /// <summary>
        /// Process a new Authentication trasanction.
        /// </summary>
        /// <param name="jsRuntime">The <see cref="IJSRuntime"/> instance.</param>
        /// <param name="authorizeOptions">The <see cref="AuthorizeOptions"/> instance.</param>
        /// <returns>A <see cref="Task{TResult}"/> representing the result of the asynchronous operation.</returns>
        internal static async Task<OpenId.Models.AuthorizeOptions> Proccess(IJSRuntime jsRuntime, OpenId.Models.AuthorizeOptions authorizeOptions)
        {
            if (authorizeOptions is null)
            {
                throw new ArgumentNullException(nameof(authorizeOptions));
            }

            Utils.ValidateObject(authorizeOptions);

            bool responseTypeIncludesIdToken = authorizeOptions.ResponseType == ResponseTypes.IdToken || authorizeOptions.ResponseType == ResponseTypes.TokenAndIdToken;

            SessionAuthorizationTransaction transaction = await GenerateTransaction(
                jsRuntime,
                authorizeOptions,
                responseTypeIncludesIdToken
              ).ConfigureAwait(false);

            if (string.IsNullOrEmpty(authorizeOptions.State))
            {
                authorizeOptions.State = transaction.State;
            }

            if (responseTypeIncludesIdToken && string.IsNullOrEmpty(authorizeOptions.Nonce))
            {
                authorizeOptions.Nonce = transaction.Nonce;
            }

            return authorizeOptions;
        }

        /// <summary>
        /// Gets an stored trasanction from localstorage.
        /// </summary>
        /// <param name="jsRuntime">The <see cref="IJSRuntime"/> instance.</param>
        /// <param name="clientOptions">The <see cref="ClientOptions"/> instance.</param>
        /// <param name="state">The state value used in the authentication flow.</param>
        /// <returns>A <see cref="Task{TResult}"/> representing the result of the asynchronous operation.</returns>
        internal static async Task<SessionAuthorizationTransaction> GetStoredTransactionAsync(IJSRuntime jsRuntime, ClientOptions clientOptions, string state)
        {
            SessionAuthorizationTransaction result = await Storage.GetItemAsync<SessionAuthorizationTransaction>(jsRuntime, $"{clientOptions.Namespace}{state}").ConfigureAwait(false);
            await Storage.RemoveItem(jsRuntime, $"{clientOptions.Namespace}{state}").ConfigureAwait(false);
            return result;
        }

        private static async Task<SessionAuthorizationTransaction> GenerateTransaction(
            IJSRuntime jsRuntime,
            OpenId.Models.AuthorizeOptions authorizeOptions,
            bool responseTypeIncludesIdToken)
        {
            string lastUsedConnection = string.IsNullOrEmpty(authorizeOptions.Realm) ? authorizeOptions.Connection : authorizeOptions.Realm;

            string appState = string.IsNullOrEmpty(authorizeOptions.AppState) ? Auth0.CommonAuthentication.GenerateNonce(authorizeOptions.KeyLength) : authorizeOptions.AppState;
            authorizeOptions.State = string.IsNullOrEmpty(authorizeOptions.State) ? Auth0.CommonAuthentication.GenerateNonce(authorizeOptions.KeyLength) : authorizeOptions.State;
            string nonce = responseTypeIncludesIdToken ? string.IsNullOrEmpty(authorizeOptions.Nonce) ? Auth0.CommonAuthentication.GenerateNonce(authorizeOptions.KeyLength) : authorizeOptions.Nonce : null;

            SessionAuthorizationTransaction transaction = new SessionAuthorizationTransaction()
            {
                Nonce = nonce,
                AppState = appState,
                State = authorizeOptions.State,
                CodeVerifier = authorizeOptions.CodeVerifier,
                RedirectUri = authorizeOptions.RedirectUri,
                Connnection = lastUsedConnection,
            };

            await Storage.SetItem(
                jsRuntime,
                $"{authorizeOptions.Namespace}{authorizeOptions.State}",
                transaction
                ).ConfigureAwait(false);

            return transaction;
        }
    }
}
