// Based on ASP.NET Core, which is copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace ISchemm.AspNetCore.Authentication.Tumblr
{
    /// <summary>
    /// Default <see cref="TumblrEvents"/> implementation.
    /// </summary>
    public class TumblrEvents : RemoteAuthenticationEvents
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<TumblrCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Func<RedirectContext<TumblrOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

        /// <summary>
        /// Invoked whenever Tumblr successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task CreatingTicket(TumblrCreatingTicketContext context) => OnCreatingTicket(context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Tumblr handler
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<TumblrOptions> context) => OnRedirectToAuthorizationEndpoint(context);
    }
}
