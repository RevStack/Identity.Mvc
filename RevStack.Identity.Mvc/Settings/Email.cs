using System;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class Email
    {
        public static string NewLine
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.NewLine"];
                if (!string.IsNullOrEmpty(result)) return "<br>";
                return Environment.NewLine;
            }
        }
        public static string Duplicate
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Duplicate"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Email address already exists";
            }
        }
        public static string Valediction
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Email.Valediction"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "The Asp.net Developer Team";
            }
        }

    }
}
