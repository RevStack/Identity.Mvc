using System;
using System.Collections.Generic;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class Configuration
    {
        public static bool IsAzureHosted
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Configuration.IsAzureHosted"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static string Identifier
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Configuration.Identifier"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Asp.net Identity";
            }
        }
    }
}
