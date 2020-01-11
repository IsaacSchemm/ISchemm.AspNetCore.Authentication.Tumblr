// Based on ASP.NET Core, which is copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace ISchemm.AspNetCore.Authentication.Tumblr
{
    /// <summary>
    /// Options for the Tumblr authentication handler.
    /// </summary>
    public class TumblrOptions : RemoteAuthenticationOptions
    {
        private const string DefaultStateCookieName = "__TumblrState";

        private CookieBuilder _stateCookieBuilder;

        /// <summary>
        /// Initializes a new instance of the <see cref="TumblrOptions"/> class.
        /// </summary>
        public TumblrOptions()
        {
            CallbackPath = new PathString("/signin-tumblr");
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Events = new TumblrEvents();

            ClaimActions.MapJsonKey(ClaimTypes.Email, "email", ClaimValueTypes.Email);

            _stateCookieBuilder = new TumblrCookieBuilder(this)
            {
                Name = DefaultStateCookieName,
                SecurePolicy = CookieSecurePolicy.SameAsRequest,
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                IsEssential = true,
            };
        }

        /// <summary>
        /// Gets or sets the consumer key used to communicate with Tumblr.
        /// </summary>
        /// <value>The consumer key used to communicate with Tumblr.</value>
        public string ConsumerKey { get; set; }

        /// <summary>
        /// Gets or sets the consumer secret used to sign requests to Tumblr.
        /// </summary>
        /// <value>The consumer secret used to sign requests to Tumblr.</value>
        public string ConsumerSecret { get; set; }

        /// <summary>
        /// Enables the retrieval user details during the authentication process.
        /// </summary>
        public bool RetrieveUserDetails { get; set; }

        /// <summary>
        /// A collection of claim actions used to select values from the json user data and create Claims.
        /// </summary>
        public ClaimActionCollection ClaimActions { get; } = new ClaimActionCollection();

        /// <summary>
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="TumblrEvents"/> used to handle authentication events.
        /// </summary>
        public new TumblrEvents Events
        {
            get => (TumblrEvents)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Determines the settings used to create the state cookie before the
        /// cookie gets added to the response.
        /// </summary>
        public CookieBuilder StateCookie
        {
            get => _stateCookieBuilder;
            set => _stateCookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Added the validate method to ensure that the customer key and customer secret values are not not empty for the Tumblr authentication middleware
        /// </summary>
        public override void Validate()
        {
            base.Validate();
            if (string.IsNullOrEmpty(ConsumerKey))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", nameof(ConsumerKey)), nameof(ConsumerKey));
            }

            if (string.IsNullOrEmpty(ConsumerSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided.", nameof(ConsumerSecret)), nameof(ConsumerSecret));
            }
        }

        private class TumblrCookieBuilder : CookieBuilder
        {
            private readonly TumblrOptions _tumblrOptions;

            public TumblrCookieBuilder(TumblrOptions tumblrOptions)
            {
                _tumblrOptions = tumblrOptions;
            }

            public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
            {
                var options = base.Build(context, expiresFrom);
                if (!Expiration.HasValue)
                {
                    options.Expires = expiresFrom.Add(_tumblrOptions.RemoteAuthenticationTimeout);
                }
                return options;
            }
        }
    }
}
