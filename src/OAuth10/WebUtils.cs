using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;

namespace MSiccDev.Security.OAuth10
{
    public static class WebUtils
    {
        #region Public Methods

        public static IEnumerable<WebParameter> ParseQueryString(Uri uri)
        {
            if (uri is null) { throw new ArgumentNullException(nameof(uri)); }

            NameValueCollection parsedQuery = HttpUtility.ParseQueryString(uri.Query);
            var queryStringParameters =
                parsedQuery.AllKeys.SelectMany(parsedQuery.GetValues, (key, value) => new { key, value });

            foreach (var param in queryStringParameters)
            {
                yield return new WebParameter(param.key, param.value);
            }
        }

        #endregion Public Methods
    }
}