using System.Configuration;
using System.IO;
using System.Net;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;

namespace MSiccDev.Security.OAuth10.IntegrationTests
{
    //[Ignore("Requires external OAuth key and secret")]
    [TestFixture]
    public class OAuthTests
    {
        #region Private Fields

        private const string _baseUrl = "https://api.twitter.com/oauth/{0}";
        private const string _callbackUrl = "https://msiccdev.net/callback";
        private string _consumerKey;
        private string _consumerSecret;

        #endregion Private Fields

        #region Public Methods

        [Test]
        public void Can_get_request_token_with_http_header()
        {
            var client = new OAuthRequest
            {
                Method = "GET",
                ConsumerKey = _consumerKey,
                ConsumerSecret = _consumerSecret,
                RequestUrl = string.Format(_baseUrl, "request_token"),
                CallbackUrl = _callbackUrl
            };

            var auth = client.GetAuthorizationHeader();

            var request = (HttpWebRequest)WebRequest.Create(client.RequestUrl);

            request.Headers.Add("Authorization", auth);

            HttpWebResponse response;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
                var reader = new StreamReader(response.GetResponseStream());
                var content = reader.ReadToEnd();
            }
            catch (System.Exception ex)
            {
                if (ex is WebException wex)
                {
                    var reader = new StreamReader(wex.Response.GetResponseStream());
                    _ = reader.ReadToEnd();
                }

                throw;
            }

            Assert.IsNotNull(response);

            Assert.AreEqual(200, (int)response.StatusCode);
        }

        [Test]
        public void Can_get_request_token_with_query()
        {
            var client = OAuthRequest.ForRequestToken(_consumerKey, _consumerSecret, _callbackUrl);

            client.RequestUrl = string.Format(_baseUrl, "request_token");

            var auth = client.GetAuthorizationQuery();

            var url = client.RequestUrl + "?" + auth;

            var request = (HttpWebRequest)WebRequest.Create(url);

            HttpWebResponse response;
            try
            {
                response = (HttpWebResponse)request.GetResponse();

                var reader = new StreamReader(response.GetResponseStream());
                var content = reader.ReadToEnd();
            }
            catch (System.Exception ex)
            {
                if (ex is WebException wex)
                {
                    var reader = new StreamReader(wex.Response.GetResponseStream());
                    _ = reader.ReadToEnd();
                }

                throw;
            }

            Assert.IsNotNull(response);

            Assert.AreEqual(200, (int)response.StatusCode);
        }

        [SetUp]
        public void SetUp()
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", false, false)
                .Build();
            _consumerKey = config["ConsumerKey"];
            _consumerSecret = config["ConsumerSecret"];
        }

        #endregion Public Methods
    }
}