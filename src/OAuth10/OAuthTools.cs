using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace MSiccDev.Security.OAuth10
{
    /// <summary>
    /// A general purpose toolset for creating components of an OAuth request.
    /// </summary>
    /// <seealso href="http://oauth.net/" />
    public static class OAuthTools
    {
        #region Private Fields

        private const string _alphaNumeric = _upper + _lower + _digit;
        private const string _digit = "1234567890";
        private const string _lower = "abcdefghijklmnopqrstuvwxyz";
        private const string _unreserved = _alphaNumeric + "-._~";
        private const string _upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        private static readonly Encoding _encoding = Encoding.UTF8;
        private static readonly Random _random;
        private static readonly object _randomLock = new object();

        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        #endregion Private Fields

        #region Private Methods

        private static string Concatenate(ICollection<WebParameter> collection, string separator, string spacer)
        {
            var sb = new StringBuilder();

            var total = collection.Count;
            var count = 0;

            foreach (var item in collection)
            {
#pragma warning disable IDE0058 // Expression value is never used
                sb.Append(item.Name);
                sb.Append(separator);
                sb.Append(item.Value);
#pragma warning restore IDE0058 // Expression value is never used

                count++;
                if (count < total)
                {
#pragma warning disable IDE0058 // Expression value is never used
                    sb.Append(spacer);
#pragma warning restore IDE0058 // Expression value is never used
                }
            }

            return sb.ToString();
        }

        private static bool EqualsIgnoreCase(string left, string right)
        {
            return CultureInfo.InvariantCulture.CompareInfo.Compare(left, right, CompareOptions.IgnoreCase) == 0;
        }

        private static string HashWith(string input, HashAlgorithm algorithm)
        {
            var data = Encoding.UTF8.GetBytes(input);
            var hash = algorithm.ComputeHash(data);
            return Convert.ToBase64String(hash);
        }

        private static string PercentEncode(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s);
            var sb = new StringBuilder();
            foreach (var b in bytes)
            {
                // Supports proper encoding of special characters (\n\r\t\b)
                if ((b > 7 && b < 11) || b == 13)
                {
#pragma warning disable IDE0058 // Expression value is never used
                    sb.Append(string.Format("%0{0:X}", b));
#pragma warning restore IDE0058 // Expression value is never used
                }
                else
                {
#pragma warning disable IDE0058 // Expression value is never used
                    sb.Append(string.Format("%{0:X}", b));
#pragma warning restore IDE0058 // Expression value is never used
                }
            }
            return sb.ToString();
        }

        private static long ToUnixTime(DateTime dateTime)
        {
            var timeSpan = (dateTime - new DateTime(1970, 1, 1));
            var timestamp = (long)timeSpan.TotalSeconds;

            return timestamp;
        }

        #endregion Private Methods

        #region Public Constructors

        static OAuthTools()
        {
            var bytes = new byte[4];
            _rng.GetBytes(bytes);
            _random = new Random(BitConverter.ToInt32(bytes, 0));
        }

        #endregion Public Constructors

        /// <summary>
        /// All text parameters are UTF-8 encoded (per section 5.1).
        /// </summary>
        /// <seealso href="http://www.hueniverse.com/hueniverse/2008/10/beginners-gui-1.html" />
#if !WINRT
#else
        private static readonly BinaryStringEncoding _encoding = BinaryStringEncoding.Utf8;
#endif

        #region Public Methods

        /// <summary>
        /// Creates a request elements concatentation value to send with a request. This is also
        /// known as the signature base.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.3" />
        /// <seealso href="http://oauth.net/core/1.0#sig_base_example" />
        /// <param name="method">
        /// The request's HTTP method type
        /// </param>
        /// <param name="url">
        /// The request URL
        /// </param>
        /// <param name="parameters">
        /// The request's parameters
        /// </param>
        /// <returns>
        /// A signature base string
        /// </returns>
        public static string ConcatenateRequestElements(string method, string url, WebParameterCollection parameters)
        {
            var sb = new StringBuilder();

            // Separating &'s are not URL encoded
            var requestMethod = string.Concat(method.ToUpper(), "&");
            var uri = new Uri(url);
            var requestUrl = string.Concat(UrlEncodeRelaxed(ConstructRequestUrl(uri)), "&");
            parameters.AddRange(WebUtils.ParseQueryString(uri));
            var requestParameters = UrlEncodeRelaxed(NormalizeRequestParameters(parameters));

#pragma warning disable IDE0058 // Expression value is never used
            sb.Append(requestMethod);
            sb.Append(requestUrl);
            sb.Append(requestParameters);
#pragma warning restore IDE0058 // Expression value is never used

            return sb.ToString();
        }

        /// <summary>
        /// Creates a request URL suitable for making OAuth requests. Resulting URLs must exclude
        /// port 80 or port 443 when accompanied by HTTP and HTTPS, respectively. Resulting URLs
        /// must be lower case.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.2" />
        /// <param name="url">
        /// The original request URL
        /// </param>
        /// <returns>
        /// </returns>
        public static string ConstructRequestUrl(Uri url)
        {
            if (url == null)
            {
                throw new ArgumentNullException("url");
            }

            var sb = new StringBuilder();

            var requestUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
            var qualified = string.Format(":{0}", url.Port);
            var basic = url.Scheme == "http" && url.Port == 80;
            var secure = url.Scheme == "https" && url.Port == 443;

#pragma warning disable IDE0058 // Expression value is never used
            sb.Append(requestUrl);
            sb.Append(!basic && !secure ? qualified : "");
            sb.Append(url.AbsolutePath);
#pragma warning restore IDE0058 // Expression value is never used

            return sb.ToString(); //.ToLower();
        }

        /// <summary>
        /// Generates a random 16-byte lowercase alphanumeric string.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <returns>
        /// </returns>
        public static string GetNonce()
        {
            const string chars = (_lower + _digit);

            var nonce = new char[16];
            lock (_randomLock)
            {
                for (var i = 0; i < nonce.Length; i++)
                {
                    nonce[i] = chars[_random.Next(0, chars.Length)];
                }
            }
            return new string(nonce);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret. This method is
        /// used when the token secret is currently unknown.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">
        /// The hashing method
        /// </param>
        /// <param name="signatureBase">
        /// The signature base
        /// </param>
        /// <param name="consumerSecret">
        /// The consumer key
        /// </param>
        /// <returns>
        /// </returns>
        public static string GetSignature(OAuthSignatureMethod signatureMethod, string? signatureBase, string? consumerSecret)
        {
            if (string.IsNullOrWhiteSpace(signatureBase))
                throw new NullReferenceException($"parameter {nameof(signatureBase)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(consumerSecret))
                throw new NullReferenceException($"parameter {nameof(consumerSecret)} must not be null, empty or whitespace");

            return GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, signatureBase, consumerSecret, null);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret. This method is
        /// used when the token secret is currently unknown.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">
        /// The hashing method
        /// </param>
        /// <param name="signatureTreatment">
        /// The treatment to use on a signature value
        /// </param>
        /// <param name="signatureBase">
        /// The signature base
        /// </param>
        /// <param name="consumerSecret">
        /// The consumer key
        /// </param>
        /// <returns>
        /// </returns>
        public static string GetSignature(OAuthSignatureMethod signatureMethod, OAuthSignatureTreatment signatureTreatment, string? signatureBase, string? consumerSecret)
        {
            if (string.IsNullOrWhiteSpace(signatureBase))
                throw new NullReferenceException($"parameter {nameof(signatureBase)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(consumerSecret))
                throw new NullReferenceException($"parameter {nameof(consumerSecret)} must not be null, empty or whitespace");

            return GetSignature(signatureMethod, signatureTreatment, signatureBase, consumerSecret, null);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret and a known
        /// token secret.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">
        /// The hashing method
        /// </param>
        /// <param name="signatureBase">
        /// The signature base
        /// </param>
        /// <param name="consumerSecret">
        /// The consumer secret
        /// </param>
        /// <param name="tokenSecret">
        /// The token secret
        /// </param>
        /// <returns>
        /// </returns>
#pragma warning disable IDE0060 // Remove unused parameter

        public static string GetSignature(OAuthSignatureMethod signatureMethod, string? signatureBase, string? consumerSecret, string? tokenSecret)
#pragma warning restore IDE0060 // Remove unused parameter
        {
            if (string.IsNullOrWhiteSpace(consumerSecret))
                throw new NullReferenceException($"parameter {nameof(consumerSecret)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(tokenSecret))
                throw new NullReferenceException($"parameter {nameof(tokenSecret)} must not be null, empty or whitespace");

            return GetSignature(signatureMethod, OAuthSignatureTreatment.Escaped, consumerSecret, tokenSecret);
        }

        /// <summary>
        /// Creates a signature value given a signature base and the consumer secret and a known
        /// token secret.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.2" />
        /// <param name="signatureMethod">
        /// The hashing method
        /// </param>
        /// <param name="signatureTreatment">
        /// The treatment to use on a signature value
        /// </param>
        /// <param name="signatureBase">
        /// The signature base
        /// </param>
        /// <param name="consumerSecret">
        /// The consumer secret
        /// </param>
        /// <param name="tokenSecret">
        /// The token secret
        /// </param>
        /// <returns>
        /// </returns>
        public static string GetSignature(OAuthSignatureMethod signatureMethod, OAuthSignatureTreatment signatureTreatment, string? signatureBase,
                                          string? consumerSecret, string? tokenSecret)
        {
            if (string.IsNullOrWhiteSpace(signatureBase))
                throw new NullReferenceException($"parameter {nameof(signatureBase)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(consumerSecret))
                throw new NullReferenceException($"parameter {nameof(consumerSecret)} must not be null, empty or whitespace");

            if (string.IsNullOrWhiteSpace(tokenSecret))
                tokenSecret = string.Empty;

            string signature;
            switch (signatureMethod)
            {
                case OAuthSignatureMethod.HmacSha1:
                    {
                        consumerSecret = UrlEncodeRelaxed(consumerSecret);
                        tokenSecret = UrlEncodeRelaxed(tokenSecret);
                        var key = string.Concat(consumerSecret, "&", tokenSecret);

                        var crypto = new HMACSHA1
                        {
                            Key = _encoding.GetBytes(key)
                        };

                        signature = HashWith(signatureBase, crypto);

                        break;
                    }
                case OAuthSignatureMethod.RsaSha1:
                    signature = TextSigner.SignWithRsaSha1(signatureBase, consumerSecret);
                    break;

                default:
                    throw new NotImplementedException("Only HMAC-SHA1 and RSA-SHA1 signatures are currently supported.");
            }

            var result = signatureTreatment == OAuthSignatureTreatment.Escaped
                       ? UrlEncodeRelaxed(signature)
                       : signature;

            return result;
        }

        /// <summary>
        /// Generates a timestamp based on the current elapsed seconds since '01/01/1970 0000 GMT"
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <returns>
        /// </returns>
        public static string GetTimestamp()
        {
            return GetTimestamp(DateTime.UtcNow);
        }

        /// <summary>
        /// Generates a timestamp based on the elapsed seconds of a given time since '01/01/1970
        /// 0000 GMT"
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#nonce" />
        /// <param name="dateTime">
        /// A specified point in time.
        /// </param>
        /// <returns>
        /// </returns>
        public static string GetTimestamp(DateTime dateTime)
        {
            var timestamp = ToUnixTime(dateTime);
            return timestamp.ToString();
        }

        /// <summary>
        /// Sorts a collection of key-value pairs by name, and then value if equal, concatenating
        /// them into a single string. This string should be encoded prior to, or after
        /// normalization is run.
        /// </summary>
        /// <seealso href="http://oauth.net/core/1.0#rfc.section.9.1.1" />
        /// <param name="parameters">
        /// </param>
        /// <returns>
        /// </returns>
        public static string NormalizeRequestParameters(WebParameterCollection parameters)
        {
            var copy = SortParametersExcludingSignature(parameters);
            var concatenated = Concatenate(copy, "=", "&");
            return concatenated;
        }

        /// <summary>
        /// Sorts a <see cref="WebParameterCollection" /> by name, and then value if equal.
        /// </summary>
        /// <param name="parameters">
        /// A collection of parameters to sort
        /// </param>
        /// <returns>
        /// A sorted parameter collection
        /// </returns>
        public static WebParameterCollection SortParametersExcludingSignature(WebParameterCollection parameters)
        {
            var copy = new WebParameterCollection(parameters);
            var exclusions = copy.Where(n => EqualsIgnoreCase(n.Name, "oauth_signature"));

#pragma warning disable IDE0058 // Expression value is never used
            copy.RemoveAll(exclusions);
#pragma warning restore IDE0058 // Expression value is never used

            foreach (var parameter in copy)
            {
                parameter.Value = UrlEncodeStrict(parameter.Value);
            }

            copy.Sort((x, y) => x.Name.Equals(y.Name) ? x.Value.CompareTo(y.Value) : x.Name.CompareTo(y.Name));
            return copy;
        }

        /// <summary>
        /// URL encodes a string based on section 5.1 of the OAuth spec. Namely, percent encoding
        /// with [RFC3986], avoiding unreserved characters, upper-casing hexadecimal characters, and
        /// UTF-8 encoding for text value pairs.
        /// </summary>
        /// <param name="value">
        /// </param>
        /// <seealso href="http://oauth.net/core/1.0#encoding_parameters" />
        public static string UrlEncodeRelaxed(string value)
        {
            var escaped = Uri.EscapeDataString(value);

            // LinkedIn users have problems because it requires escaping brackets
            escaped = escaped.Replace("(", PercentEncode("("))
                             .Replace(")", PercentEncode(")"));

            return escaped;
        }

        /// <summary>
        /// URL encodes a string based on section 5.1 of the OAuth spec. Namely, percent encoding
        /// with [RFC3986], avoiding unreserved characters, upper-casing hexadecimal characters, and
        /// UTF-8 encoding for text value pairs.
        /// </summary>
        /// <param name="value">
        /// </param>
        /// <seealso href="http://oauth.net/core/1.0#encoding_parameters" />
        public static string UrlEncodeStrict(string value)
        {
            // [JD]: We need to escape the apostrophe as well or the signature will fail
            var original = value;
            var ret = original.OfType<char>().Where(
                c => !_unreserved.OfType<char>().Contains(c) && c != '%').Aggregate(
                    value, (current, c) => current.Replace(
                          c.ToString(), PercentEncode(c.ToString())
                          ));

            return ret.Replace("%%", "%25%"); // Revisit to encode actual %'s
        }

        #endregion Public Methods
    }
}