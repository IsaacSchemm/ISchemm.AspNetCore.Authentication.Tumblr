// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace ISchemm.AspNetCore.Authentication.Tumblr
{
    public static class TumblrDefaults
    {
        public const string AuthenticationScheme = "Tumblr";

        public static readonly string DisplayName = "Tumblr";

        // https://developer.twitter.com/en/docs/basics/authentication/api-reference/request_token
        internal const string RequestTokenEndpoint = "https://api.twitter.com/oauth/request_token";

        // https://developer.twitter.com/en/docs/basics/authentication/api-reference/authenticate
        internal const string AuthenticationEndpoint = "https://api.twitter.com/oauth/authenticate?oauth_token=";

        // https://developer.twitter.com/en/docs/basics/authentication/api-reference/access_token
        internal const string AccessTokenEndpoint = "https://api.twitter.com/oauth/access_token";
    }
}
