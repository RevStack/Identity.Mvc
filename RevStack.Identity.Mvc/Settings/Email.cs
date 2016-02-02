using System;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class Email
    {
        public static bool EnableConfirmation
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.EnableConfirmation"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static string Subject
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Subject"];
                if (result != null) return result;
                return "Confirm your account";
            }
        }
        public static string Body
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Body"];
                if (result != null) return result;
                return "Account Confirmation";
            }
        }
        public static string Notice
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Notice"];
                if (result != null) return result;
                return "Check your email and confirm your account.You must be confirmed before you can log in.";
            }
        }
        public static string Cookie
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Cookie"];
                if (result != null) return result;
                return "SignUpConfirmEmail";
            }
        }
        public static string Valediction
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Valediction"];
                if (result != null) return result;
                return "The Asp.net Developer Team";
            }
        }

    }
}
