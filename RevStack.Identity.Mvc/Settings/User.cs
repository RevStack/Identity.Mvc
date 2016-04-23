using System;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class User
    {
        public static string NotFound
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.User.NotFound"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Failed to find an available user for this request";
            }
        }
        public static string Duplicate
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.User.Duplicate"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "User Name Already Exists";
            }
        }
        public static string Locked
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.User.Locked"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "This account is currently locked";
            }
        }
        public static string InvalidLogin
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.User.Login.Invalid"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Invalid Login Request";
            }
        }
    }
}
