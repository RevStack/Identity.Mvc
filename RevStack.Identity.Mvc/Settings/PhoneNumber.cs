using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class PhoneNumber
    {
        public static string AddSuccess
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.PhoneNumber.AddSuccess"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Your phone number has been added.";
            }
        }

        public static string RemoveSuccess
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.PhoneNumber.RemoveSuccess"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Your phone number has been removed.";
            }
        }

        public static string Verify
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.PhoneNumber.Verify"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Please verify your phone number.";
            }
        }

    }
}
