using System;
using Blazor.OpenId.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Blazor.OpenId
{
    /// <summary>
    /// Class containing extension methods for Blazor.Openid default initialization.
    /// </summary>
    public static class BlazoOpenIdBuilderExtensions
    {
        /// <summary>
        /// Add Blazor.Openid default services.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> instance.</param>
        /// <param name="options">The <see cref="Action"/> containing a <see cref="OpenidClientOptions"/> instance.</param>
        /// <returns>A <see cref="IServiceCollection"/> instance.</returns>
        public static IServiceCollection AddBlazorOpenid(this IServiceCollection services, Action<OpenidClientOptions> options = null)
        {
            services.AddBlazorOpenidClientOptions(options);

            return services.AddBlazorOpenid();
        }

        /// <summary>
        /// Add Blazor.Openid default services.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> instance.</param>
        /// <returns>A <see cref="IServiceCollection"/> instance.</returns>
        public static IServiceCollection AddBlazorOpenid(this IServiceCollection services)
        {
            services.AddScoped<IAuthenticationService, Blazor.OpenId.AuthenticationService>();
            services.AddScoped<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider, AuthenticationStateProvider>();

            return services;
        }

        /// <summary>
        /// Add Blazor.Openid client options.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> instance.</param>
        /// <param name="options">The <see cref="Action"/> containing a <see cref="OpenidClientOptions"/> instance.</param>
        /// <returns>A <see cref="IServiceCollection"/> instance.</returns>
        public static IServiceCollection AddBlazorOpenidClientOptions(this IServiceCollection services, Action<OpenidClientOptions> options = null)
        {
            services.Configure(options);
            services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<OpenidClientOptions>>().Value);

            return services;
        }

        /// <summary>
        /// Add Blazor.Openid client options.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> instance.</param>
        /// <param name="options">The <see cref="OpenidClientOptions"/> instance.</param>
        /// <returns>A <see cref="IServiceCollection"/> instance.</returns>
        public static IServiceCollection AddBlazorOpenidClientOptions(this IServiceCollection services, OpenidClientOptions options = null)
        {
            services.AddSingleton(resolver => options ?? resolver.GetRequiredService<IOptions<OpenidClientOptions>>().Value);
            return services;
        }

    }
}
