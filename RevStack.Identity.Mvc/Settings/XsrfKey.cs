using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class XsrfKey
    {
        public static string Key
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.XsrfKey"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "XsrfId";
            }
        }
    }
}
