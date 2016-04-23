using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class ForgotPassword
    {
        public static string Subject
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.ForgotPassword.Subject"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Reset Password";
            }
        }

        public static string Body
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.ForgotPassword.Body"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Request Password";
            }
        }
    }
}
