using System;
using System.Diagnostics;

namespace MSiccDev.Security.OAuth10
{
    public class WebParameter
    {
        #region Public Constructors

        public WebParameter(string name, string value)
        {
            this.Name = name;
            this.Value = value;
        }

        #endregion Public Constructors

        #region Public Properties

        public string Name { get; private set; }
        public string Value { get; set; }

        #endregion Public Properties
    }
}