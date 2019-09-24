using Blazor.OpenId;
using Microsoft.AspNetCore.Components.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Examples.AspNetCoreHosted.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddBlazorOpenid(options =>
            {
                // Do not include http or http ://
                options.Domain = "[Your-Domain]";

                options.ClientId = "[Your-Client-Id]";

                options.SlidingExpiration = true;

                options.Scope = "[Your-Scopes]";  // By default openid profile email
                options.RequestMode = Blazor.OpenId.Models.RequestModes.Form_Post;

            });

            // Policy based authorization, learn more here: https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-3.0
            services.AddAuthorizationCore(options =>
            {
                options.AddPolicy("read:weather_forecast", policy => policy.RequireClaim("read:weather_forecast"));
                options.AddPolicy("execute:increment_counter", policy => policy.RequireClaim("execute:increment_counter"));
            });
        }

        public void Configure(IComponentsApplicationBuilder app)
        {
            app.AddComponent<App>("app");
        }
    }
}
