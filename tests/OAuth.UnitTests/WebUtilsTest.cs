using System;
using System.Linq;
using NUnit.Framework;

namespace MSiccDev.Security.OAuth10.Tests
{
    [TestFixture]
    public class WebUtilsTest
    {
        #region Public Methods

        [TestCase(null)]
        public void ParseQueryStringThrowsArgumentNullException(string invalidUrl)
        {
            _ = Assert.Throws<ArgumentNullException>(() => WebUtils.ParseQueryString(new Uri(invalidUrl)).ToList());
        }

        [TestCase("https://www.google.com", 0)]
        [TestCase("https://www.google.com/", 0)]
        [TestCase("https://www.google.com/?a=b", 1)]
        [TestCase("https://www.google.com/?a=b&c=d", 2)]
        [TestCase("https://www.google.com/?a=b&c=d&e=f", 3)]
        [TestCase("https://www.google.com/?a=b&c=d&e=f&g=", 4)]
        [TestCase("https://www.url.com/search?jql=assignee=User&user_id=UserId", 2)]
        public void ParsesQueryString(string url, int expectedQueryParametersCount)
        {
            Assert.AreEqual(expectedQueryParametersCount, WebUtils.ParseQueryString(new Uri(url)).Count());
        }

        #endregion Public Methods
    }
}