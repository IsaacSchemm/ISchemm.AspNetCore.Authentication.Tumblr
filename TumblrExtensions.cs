// Based on ASP.NET Core, which is copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using ISchemm.AspNetCore.Authentication.Tumblr;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class TumblrExtensions
    {
        public static AuthenticationBuilder AddTumblr(this AuthenticationBuilder builder)
            => builder.AddTumblr(TumblrDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddTumblr(this AuthenticationBuilder builder, Action<TumblrOptions> configureOptions)
            => builder.AddTumblr(TumblrDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddTumblr(this AuthenticationBuilder builder, string authenticationScheme, Action<TumblrOptions> configureOptions)
            => builder.AddTumblr(authenticationScheme, TumblrDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddTumblr(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<TumblrOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TumblrOptions>, TumblrPostConfigureOptions>());
            return builder.AddRemoteScheme<TumblrOptions, TumblrHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
