// Based on ASP.NET Core, which is copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace ISchemm.AspNetCore.Authentication.Tumblr
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class TumblrCreatingTicketContext : ResultContext<TumblrOptions>
    {
        /// <summary>
        /// Initializes a <see cref="TumblrCreatingTicketContext"/>
        /// </summary>
        /// <param name="context">The HTTP environment</param>
        /// <param name="scheme">The scheme data</param>
        /// <param name="options">The options for Tumblr</param>
        /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
        /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
        /// <param name="userId">Tumblr user ID</param>
        /// <param name="screenName">Tumblr screen name</param>
        /// <param name="accessToken">Tumblr access token</param>
        /// <param name="accessTokenSecret">Tumblr access token secret</param>
        /// <param name="user">User details</param>
        public TumblrCreatingTicketContext(
            HttpContext context,
            AuthenticationScheme scheme,
            TumblrOptions options,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            string userId,
            string screenName,
            string accessToken,
            string accessTokenSecret,
            JsonElement user)
            : base(context, scheme, options)
        {
            UserId = userId;
            ScreenName = screenName;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
            User = user;
            Principal = principal;
            Properties = properties;
        }

        /// <summary>
        /// Gets the Tumblr user ID
        /// </summary>
        public string UserId { get; }

        /// <summary>
        /// Gets the Tumblr screen name
        /// </summary>
        public string ScreenName { get; }

        /// <summary>
        /// Gets the Tumblr access token
        /// </summary>
        public string AccessToken { get; }

        /// <summary>
        /// Gets the Tumblr access token secret
        /// </summary>
        public string AccessTokenSecret { get; }

        /// <summary>
        /// Gets the JSON-serialized user or an empty
        /// <see cref="JsonElement"/> if it is not available.
        /// </summary>
        public JsonElement User { get; }
    }
}
