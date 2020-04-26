using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;

namespace MSiccDev.Security.OAuth10
{
    /// <summary>
    /// A request wrapper for the OAuth 1.0a specification.
    /// </summary>
    /// <seealso href="http://oauth.net/" />
    public class OAuthRequest
    {
        #region Private Methods

        private void AddAuthParameters(ICollection<WebParameter> parameters, string? timestamp, string? nonce)
        {
            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
                throw new NullReferenceException($"{nameof(this.ConsumerKey)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(timestamp))
                throw new NullReferenceException($"parameter {nameof(timestamp)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(nonce))
                throw new NullReferenceException($"parameter {nameof(nonce)} must not be null, empty or whitespace");

            var authParameters = new WebParameterCollection
                                     {
                                         new WebParameter("oauth_consumer_key", this.ConsumerKey),
                                         new WebParameter("oauth_nonce", nonce),
                                         new WebParameter("oauth_signature_method", ToRequestValue(this.SignatureMethod)),
                                         new WebParameter("oauth_timestamp", timestamp),
                                         new WebParameter("oauth_version", this.Version ?? "1.0")
                                     };

            if (!string.IsNullOrWhiteSpace(this.Token))
                authParameters.Add(new WebParameter("oauth_token", this.Token));

            if (!string.IsNullOrWhiteSpace(this.CallbackUrl))
                authParameters.Add(new WebParameter("oauth_callback", this.CallbackUrl));

            if (!string.IsNullOrWhiteSpace(this.Verifier))
                authParameters.Add(new WebParameter("oauth_verifier", this.Verifier));

            if (!string.IsNullOrWhiteSpace(this.SessionHandle))
                authParameters.Add(new WebParameter("oauth_session_handle", this.SessionHandle));

            foreach (var authParameter in authParameters)
                parameters.Add(authParameter);
        }

        private void AddXAuthParameters(ICollection<WebParameter> parameters, string? timestamp, string? nonce)
        {
            if (string.IsNullOrWhiteSpace(this.ClientUsername))
                throw new NullReferenceException($"{nameof(this.ClientUsername)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(this.ClientPassword))
                throw new NullReferenceException($"{nameof(this.ClientPassword)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
                throw new NullReferenceException($"{nameof(this.ConsumerKey)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(timestamp))
                throw new NullReferenceException($"parameter {nameof(timestamp)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(nonce))
                throw new NullReferenceException($"parameter {nameof(nonce)} must not be null, empty or whitespace");

            var authParameters = new WebParameterCollection
                                     {
                                         new WebParameter("x_auth_username", this.ClientUsername),
                                         new WebParameter("x_auth_password", this.ClientPassword),
                                         new WebParameter("x_auth_mode", "client_auth"),
                                         new WebParameter("oauth_consumer_key", this.ConsumerKey),
                                         new WebParameter("oauth_signature_method", ToRequestValue(this.SignatureMethod)),
                                         new WebParameter("oauth_timestamp", timestamp),
                                         new WebParameter("oauth_nonce", nonce),
                                         new WebParameter("oauth_version", this.Version ?? "1.0")
                                     };

            foreach (var authParameter in authParameters)
                parameters.Add(authParameter);
        }

#pragma warning disable CS8602 // Dereference of a possibly null reference.
#pragma warning disable CS8604 // Possible null reference argument.

        private string GetNewSignature(WebParameterCollection parameters)
        {
            var timestamp = OAuthTools.GetTimestamp();

            var nonce = OAuthTools.GetNonce();

            AddAuthParameters(parameters, timestamp, nonce);

            var signatureBase = OAuthTools.ConcatenateRequestElements(this.Method.ToUpperInvariant(), this.RequestUrl, parameters);

            var signature = OAuthTools.GetSignature(this.SignatureMethod, this.SignatureTreatment, signatureBase, this.ConsumerSecret, this.TokenSecret);

            return signature;
        }

        private string GetNewSignatureXAuth(WebParameterCollection parameters)
        {
            var timestamp = OAuthTools.GetTimestamp();

            var nonce = OAuthTools.GetNonce();

            AddXAuthParameters(parameters, timestamp, nonce);

            var signatureBase = OAuthTools.ConcatenateRequestElements(this.Method.ToUpperInvariant(), this.RequestUrl, parameters);

            var signature = OAuthTools.GetSignature(this.SignatureMethod, this.SignatureTreatment, signatureBase, this.ConsumerSecret, this.TokenSecret);

            return signature;
        }

#pragma warning restore CS8604 // Possible null reference argument.
#pragma warning restore CS8602 // Dereference of a possibly null reference.

        private void ValidateAccessRequestState()
        {
            if (string.IsNullOrWhiteSpace(this.Method))
            {
                throw new ArgumentException("You must specify an HTTP method");
            }

            if (string.IsNullOrWhiteSpace(this.RequestUrl))
            {
                throw new ArgumentException("You must specify an access token URL");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
            {
                throw new ArgumentException("You must specify a consumer key");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerSecret))
            {
                throw new ArgumentException("You must specify a consumer secret");
            }

            if (string.IsNullOrWhiteSpace(this.Token))
            {
                throw new ArgumentException("You must specify a token");
            }
        }

        private void ValidateClientAuthAccessRequestState()
        {
            if (string.IsNullOrWhiteSpace(this.Method))
            {
                throw new ArgumentException("You must specify an HTTP method");
            }

            if (string.IsNullOrWhiteSpace(this.RequestUrl))
            {
                throw new ArgumentException("You must specify an access token URL");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
            {
                throw new ArgumentException("You must specify a consumer key");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerSecret))
            {
                throw new ArgumentException("You must specify a consumer secret");
            }

            if (string.IsNullOrWhiteSpace(this.ClientUsername) || string.IsNullOrWhiteSpace(this.ClientPassword))
            {
                throw new ArgumentException("You must specify user credentials");
            }
        }

        private void ValidateProtectedResourceState()
        {
            if (string.IsNullOrWhiteSpace(this.Method))
            {
                throw new ArgumentException("You must specify an HTTP method");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
            {
                throw new ArgumentException("You must specify a consumer key");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerSecret))
            {
                throw new ArgumentException("You must specify a consumer secret");
            }
        }

        private void ValidateRequestState()
        {
            if (string.IsNullOrWhiteSpace(this.Method))
            {
                throw new ArgumentException("You must specify an HTTP method");
            }

            if (string.IsNullOrWhiteSpace(this.RequestUrl))
            {
                throw new ArgumentException("You must specify a request token URL");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerKey))
            {
                throw new ArgumentException("You must specify a consumer key");
            }

            if (string.IsNullOrWhiteSpace(this.ConsumerSecret))
            {
                throw new ArgumentException("You must specify a consumer secret");
            }
        }

        #endregion Private Methods

        #region Public Methods

        public static string ToRequestValue(OAuthSignatureMethod signatureMethod)
        {
            var value = signatureMethod.ToString().ToUpper();
            var shaIndex = value.IndexOf("SHA1");
            return shaIndex > -1 ? value.Insert(shaIndex, "-") : value;
        }

        #endregion Public Methods

        #region Public Properties

        public virtual string? CallbackUrl { get; set; }
        public virtual string? ClientPassword { get; set; }
        public virtual string? ClientUsername { get; set; }
        public virtual string? ConsumerKey { get; set; }
        public virtual string? ConsumerSecret { get; set; }
        public virtual string? Method { get; set; }
        public virtual string? Realm { get; set; }

        /// <seealso cref="http://oauth.net/core/1.0#request_urls" />
        public virtual string? RequestUrl { get; set; }

        public virtual string? SessionHandle { get; set; }
        public virtual OAuthSignatureMethod SignatureMethod { get; set; }
        public virtual OAuthSignatureTreatment SignatureTreatment { get; set; }
        public virtual string? Token { get; set; }
        public virtual string? TokenSecret { get; set; }
        public virtual OAuthRequestType Type { get; set; }
        public virtual string? Verifier { get; set; }
        public virtual string? Version { get; set; }

        #endregion Public Properties

        #region Authorization Header

        private string GetClientSignatureAuthorizationHeader(WebParameterCollection parameters)
        {
            var signature = GetNewSignatureXAuth(parameters);

            parameters.Add("oauth_signature", signature);

            return WriteAuthorizationHeader(parameters);
        }

        private string GetSignatureAuthorizationHeader(WebParameterCollection parameters)
        {
            var signature = GetNewSignature(parameters);

            parameters.Add("oauth_signature", signature);

            return WriteAuthorizationHeader(parameters);
        }

        private string WriteAuthorizationHeader(WebParameterCollection parameters)
        {
            var sb = new StringBuilder("OAuth ");

            if (!string.IsNullOrWhiteSpace(this.Realm))
            {
#pragma warning disable IDE0058 // Expression value is never used
                sb.AppendFormat("realm=\"{0}\",", OAuthTools.UrlEncodeRelaxed(this.Realm));
#pragma warning restore IDE0058 // Expression value is never used
            }

            parameters.Sort((l, r) => l.Name.CompareTo(r.Name));

            if (this.Type == OAuthRequestType.ProtectedResource)
            {
                foreach (var parameter in parameters.Where(parameter =>
                                                        !string.IsNullOrWhiteSpace(parameter.Name) &&
                                                        !string.IsNullOrWhiteSpace(parameter.Value) &&
                                                        (parameter.Name.StartsWith("oauth_") || parameter.Name.StartsWith("x_auth_")) || parameter.Name == "oauth_token" && parameter.Value != null))
                {
#pragma warning disable IDE0058 // Expression value is never used
                    sb.AppendFormat("{0}=\"{1}\",", parameter.Name, parameter.Value);
#pragma warning restore IDE0058 // Expression value is never used
                }
            }
            else
            {
                foreach (var parameter in parameters.Where(parameter =>
                                                       !string.IsNullOrWhiteSpace(parameter.Name) &&
                                                       !string.IsNullOrWhiteSpace(parameter.Value) &&
                                                           (parameter.Name.StartsWith("oauth_") || parameter.Name.StartsWith("x_auth_"))))
                {
#pragma warning disable IDE0058 // Expression value is never used
                    sb.AppendFormat("{0}=\"{1}\",", parameter.Name, parameter.Value);
#pragma warning restore IDE0058 // Expression value is never used
                }
            }

#pragma warning disable IDE0058 // Expression value is never used
            sb.Remove(sb.Length - 1, 1);
#pragma warning restore IDE0058 // Expression value is never used

            var authorization = sb.ToString();
            return authorization;
        }

        public string GetAuthorizationHeader(NameValueCollection parameters)
        {
            var collection = new WebParameterCollection(parameters);

            return GetAuthorizationHeader(collection);
        }

        public string GetAuthorizationHeader(IDictionary<string, string> parameters)
        {
            var collection = new WebParameterCollection(parameters);

            return GetAuthorizationHeader(collection);
        }

        public string GetAuthorizationHeader()
        {
            var collection = new WebParameterCollection(0);

            return GetAuthorizationHeader(collection);
        }

        public string GetAuthorizationHeader(WebParameterCollection parameters)
        {
            switch (this.Type)
            {
                case OAuthRequestType.RequestToken:
                    ValidateRequestState();
                    return GetSignatureAuthorizationHeader(parameters);

                case OAuthRequestType.AccessToken:
                    ValidateAccessRequestState();
                    return GetSignatureAuthorizationHeader(parameters);

                case OAuthRequestType.ProtectedResource:
                    ValidateProtectedResourceState();
                    return GetSignatureAuthorizationHeader(parameters);

                case OAuthRequestType.ClientAuthentication:
                    ValidateClientAuthAccessRequestState();
                    return GetClientSignatureAuthorizationHeader(parameters);

                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        #endregion Authorization Header

        #region Authorization Query

        private static string WriteAuthorizationQuery(WebParameterCollection parameters)
        {
            var sb = new StringBuilder();

            parameters.Sort((l, r) => l.Name.CompareTo(r.Name));

            var count = 0;

            foreach (var parameter in parameters.Where(parameter =>
                                                       !string.IsNullOrWhiteSpace(parameter.Name) &&
                                                       !string.IsNullOrWhiteSpace(parameter.Value) &&
                                                       (parameter.Name.StartsWith("oauth_") || parameter.Name.StartsWith("x_auth_"))))
            {
                count++;
                var format = count < parameters.Count ? "{0}={1}&" : "{0}={1}";

#pragma warning disable IDE0058 // Expression value is never used
                sb.AppendFormat(format, parameter.Name, parameter.Value);
#pragma warning restore IDE0058 // Expression value is never used
            }

            var authorization = sb.ToString();
            return authorization;
        }

        private string GetAuthorizationQuery(WebParameterCollection parameters)
        {
            switch (this.Type)
            {
                case OAuthRequestType.RequestToken:
                    ValidateRequestState();
                    return GetSignatureAuthorizationQuery(parameters);

                case OAuthRequestType.AccessToken:
                    ValidateAccessRequestState();
                    return GetSignatureAuthorizationQuery(parameters);

                case OAuthRequestType.ProtectedResource:
                    ValidateProtectedResourceState();
                    return GetSignatureAuthorizationQuery(parameters);

                case OAuthRequestType.ClientAuthentication:
                    ValidateClientAuthAccessRequestState();
                    return GetClientSignatureAuthorizationQuery(parameters);

                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private string GetClientSignatureAuthorizationQuery(WebParameterCollection parameters)
        {
            var signature = GetNewSignatureXAuth(parameters);

            parameters.Add("oauth_signature", signature);

            return WriteAuthorizationQuery(parameters);
        }

        private string GetSignatureAuthorizationQuery(WebParameterCollection parameters)
        {
            var signature = GetNewSignature(parameters);

            parameters.Add("oauth_signature", signature);

            return WriteAuthorizationQuery(parameters);
        }

        public string GetAuthorizationQuery(NameValueCollection parameters)
        {
            var collection = new WebParameterCollection(parameters);

            return GetAuthorizationQuery(collection);
        }

        public string GetAuthorizationQuery(IDictionary<string, string> parameters)
        {
            var collection = new WebParameterCollection(parameters);

            return GetAuthorizationQuery(collection);
        }

        public string GetAuthorizationQuery()
        {
            var collection = new WebParameterCollection(0);

            return GetAuthorizationQuery(collection);
        }

        #endregion Authorization Query

        #region Static Helpers

        public static OAuthRequest ForAccessToken(string consumerKey, string consumerSecret, string requestToken, string requestTokenSecret, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = new OAuthRequest
            {
                Method = "GET",
                Type = OAuthRequestType.AccessToken,
                SignatureMethod = oAuthSignatureMethod,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                Token = requestToken,
                TokenSecret = requestTokenSecret
            };
            return credentials;
        }

        public static OAuthRequest ForAccessToken(string consumerKey, string consumerSecret, string requestToken, string requestTokenSecret, string verifier, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = ForAccessToken(consumerKey, consumerSecret, requestToken, requestTokenSecret, oAuthSignatureMethod);
            credentials.Verifier = verifier;
            return credentials;
        }

        public static OAuthRequest ForAccessTokenRefresh(string consumerKey, string consumerSecret, string accessToken, string accessTokenSecret, string sessionHandle, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = ForAccessToken(consumerKey, consumerSecret, accessToken, accessTokenSecret, oAuthSignatureMethod);
            credentials.SessionHandle = sessionHandle;
            return credentials;
        }

        public static OAuthRequest ForAccessTokenRefresh(string consumerKey, string consumerSecret, string accessToken, string accessTokenSecret, string sessionHandle, string verifier, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = ForAccessToken(consumerKey, consumerSecret, accessToken, accessTokenSecret, oAuthSignatureMethod);
            credentials.SessionHandle = sessionHandle;
            credentials.Verifier = verifier;
            return credentials;
        }

        public static OAuthRequest ForClientAuthentication(string consumerKey, string consumerSecret, string username, string password, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = new OAuthRequest
            {
                Method = "GET",
                Type = OAuthRequestType.ClientAuthentication,
                SignatureMethod = oAuthSignatureMethod,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                ClientUsername = username,
                ClientPassword = password
            };

            return credentials;
        }

        public static OAuthRequest ForProtectedResource(string method, string consumerKey, string consumerSecret, string accessToken, string accessTokenSecret, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = new OAuthRequest
            {
                Method = method ?? "GET",
                Type = OAuthRequestType.ProtectedResource,
                SignatureMethod = oAuthSignatureMethod,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret,
                Token = accessToken,
                TokenSecret = accessTokenSecret
            };
            return credentials;
        }

        public static OAuthRequest ForRequestToken(string consumerKey, string consumerSecret, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = new OAuthRequest
            {
                Method = "GET",
                Type = OAuthRequestType.RequestToken,
                SignatureMethod = oAuthSignatureMethod,
                SignatureTreatment = OAuthSignatureTreatment.Escaped,
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret
            };
            return credentials;
        }

        public static OAuthRequest ForRequestToken(string consumerKey, string consumerSecret, string callbackUrl, OAuthSignatureMethod oAuthSignatureMethod = OAuthSignatureMethod.HmacSha1)
        {
            var credentials = ForRequestToken(consumerKey, consumerSecret, oAuthSignatureMethod: oAuthSignatureMethod);
            credentials.CallbackUrl = callbackUrl;
            return credentials;
        }

        #endregion Static Helpers
    }
}