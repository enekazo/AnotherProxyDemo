using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Transforms;



namespace MyProxy
{

    public class Startup
    {
        private readonly IConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="Startup" /> class.
        /// </summary>
        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            // Required to supply the authentication UI in Views/*
            services.AddRazorPages();
            services.AddScoped<TokenService>();

         //   services.AddReverseProxy()
          //      .LoadFromConfig(_configuration.GetSection("ReverseProxy"));

           

          //  services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
          //      .AddCookie();
        //     services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
	      //      .AddAzureAD(options => Configuration.Bind("AzureAd", options));

            services.AddMicrosoftIdentityWebAppAuthentication(_configuration, "AzureAd");

            services.AddAuthorization(options =>
            {
                // Creates a policy called "myPolicy" that depends on having a claim "myCustomClaim" with the value "green".
                // See AccountController.Login method for where this claim is applied to the user identity
                // This policy can then be used by routes in the proxy, see "ClaimsAuthRoute" in appsettings.json
                options.AddPolicy("myPolicy", builder => builder
                   // .RequireClaim("myCustomClaim", "green")
                    .RequireAuthenticatedUser());

            
                // The default policy is to require authentication, but no additional claims
                // Uncommenting the following would have no effect
                // options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();

                // FallbackPolicy is used for routes that do not specify a policy in config
                // Make all routes that do not specify a policy to be anonymous (this is the default).
                options.FallbackPolicy = null; 
                // Or make all routes that do not specify a policy require some auth:
                // options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();            
            });
             services.AddReverseProxy()
                .LoadFromConfig(_configuration.GetSection("ReverseProxy"))
                .AddTransforms(transformBuilderContext =>
                {
                    // For each route+cluster pair decide if we want to add transforms, and if so, which?
                    // This logic is re-run each time a route is rebuilt.

                  //  transformBuilderContext.AddPathPrefix("/prefix");

                    // Only do this for routes that require auth.
                   if (string.Equals("myPolicy", transformBuilderContext.Route.AuthorizationPolicy))
                    {
                        transformBuilderContext.AddRequestTransform(async transformContext =>
                        {
                            // AuthN and AuthZ will have already been completed after request routing.
                            var ticket = transformContext.HttpContext.User;//await transformContext.HttpContext.AuthenticateAsync("AzureAd"); 
                            var tokenService = transformContext.HttpContext.RequestServices.GetRequiredService<TokenService>();
                            var token = await tokenService.GetAuthTokenAsync(ticket);
                            transformContext.ProxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                            transformContext.ProxyRequest.Headers.Add("Enekov", token);
                        });
                    }
                });
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        public void Configure(IApplicationBuilder app)
        {
            // The order of these is important as it defines the steps that will be used to handle each request
            app.UseDeveloperExceptionPage();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

           /* app.Map("{**catch-all}", api =>
            {
                api.RunProxy(async context =>
                {
                    var forwardContext = context.ForwardTo(Configuration["xyzapi"]);

                    try
                    {
                        var token = await context.GetUserAccessTokenAsync();
                        forwardContext.UpstreamRequest.SetBearerToken(token);

                        return await forwardContext.Send();
                    }
                    catch (Exception ex)
                    {
                        throw;
                    }

                });
            });*/
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapReverseProxy();
            });
        }
    }

}