using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class Login
    {
        public static bool Persistence
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Login.Persistence"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return true;
            }
        }
    }
}
