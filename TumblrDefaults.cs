// Based on ASP.NET Core, which is copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace ISchemm.AspNetCore.Authentication.Tumblr
{
    public static class TumblrDefaults
    {
        public const string AuthenticationScheme = "Tumblr";

        public static readonly string DisplayName = "Tumblr";

        internal const string RequestTokenEndpoint = "https://www.tumblr.com/oauth/request_token";

        internal const string AuthenticationEndpoint = "https://www.tumblr.com/oauth/authorize?oauth_token=";

        internal const string AccessTokenEndpoint = "https://www.tumblr.com/oauth/access_token";
    }
}
