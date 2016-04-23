using System;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class ConfirmEmail
    {
        public static bool Enable
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Confirm.Enable"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static string Subject
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Confirm.Subject"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Confirm your account";
            }
        }
        public static string Body
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Confirm.Body"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Account Confirmation";
            }
        }
        public static string Notice
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Confirm.Notice"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Check your email and confirm your account.You must be confirmed before you can log in.";
            }
        }
        public static string Cookie
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Confirm.Cookie"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "SignUpConfirmEmail";
            }
        }
    }
}
