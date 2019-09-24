# Blazor.OpenId

<img src="https://raw.githubusercontent.com/henalbrod/Blazor.Auth0/master/src/Blazor.Auth0.ClientSide/icon.png" height="150" alt="Blazor Auth0 Library" align="right"/>

This is a library for Blazor authentication with OpenId Authorization Code-Grantflow, using IdenityServer or other OpenId providers and Silent Refresh for [Blazor](http://blazor.net) over .NET Core v3.0.0 client & server-side solutions, the idea behind this is to have an easy way of using OpenId services in Blazor without the need of the js library.

[![GitHub license](https://img.shields.io/github/license/jbomhold3/Blazor.OpenId?color=blue)](https://github.com/jbomhold3/Blazor.Openid/blob/master/LICENSE)
[![Nuget](https://img.shields.io/nuget/v/Blazor-OpenId?color=green&label=Nuget%3A%20Blazor-OpenId)](https://www.nuget.org/packages/Blazor-Auth0-ClientSide)


## Prerequisites

### Blazor

>You'll want to follow the [Getting Started](https://docs.microsoft.com/en-us/aspnet/core/blazor/get-started?view=aspnetcore-3.0&tabs=visual-studio) instructions in [Blazor website](https://blazor.net)

### IdenityServer or Another OpenId Server

> You need need to setup and configure OpenId Server.  By default Blazor.OpenId redirects to the root of your application.

## Installation

Install via [Nuget](https://www.nuget.org/).

>Server Side
```bash
Install-Package Blazor-OpenId  
````

## Usage

 **Note**: Following example is for a server-side with require authenticated user implementation, for client-side and core-hosted example implementations please refer to the [examples](https://github.com/henalbrod/Blazor.Auth0/tree/master/examples)

> #### Startup.cs

```C#
// Import Blazor.Auth0
using Blazor.Auth0;
using Blazor.Auth0.Models;
// ...

public void ConfigureServices(IServiceCollection services)
{
	// Other code...

	/// This one-liner will initialize Blazor.Auth0 with all the defaults
	    services.AddBlazorOpenid(options =>
            {
                options.Domain = "[Your-Domain]";
                options.ClientId = "[Your-Client-Id]";
                options.SlidingExpiration = true;
                options.Scope = "[Your-Scopes]";  // By default openid profile email
                options.RequestMode = Blazor.OpenId.Models.RequestModes.Form_Post;
            });

	// Other code...
}

```

###
Replace App.razor content with the following code
> #### App.razor

```HTML
<Router AppAssembly="@typeof(Program).Assembly">
    <Found Context="routeData">
        <AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)">
            <Authorizing>
                <p>>Determining session state, please wait...</p>
            </Authorizing>
            <NotAuthorized>
                <h1>Sorry</h1>
                <p>You're not authorized to reach this page. You may need to log in as a different user.</p>
            </NotAuthorized>
        </AuthorizeRouteView>
    </Found>
    <NotFound>        
        <p>Sorry, there's nothing at this address.</p>        
    </NotFound>
</Router>
```

## Authors
**John J Bomhold** - OpenId implementation of Auth0 
Auth0 was created by
**Henry Alberto Rodriguez** - _Initial work_ - [GitHub](https://github.com/henalbrod) -  [Twitter](https://twitter.com/henalbrod)  - [Linkedin](https://www.linkedin.com/in/henalbrod/)

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jbomhold3/Blazor.OpenId/blob/master/LICENSE) file for details.
