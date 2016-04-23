using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class TwoFactor
    {
        public static string Success
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.TwoFactor.Success"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Your two factor authentication provider has been set.";
            }
        }

        public static string Enable
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.TwoFactor.Enable"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Two factor authentication has been enabled.";
            }
        }

        public static string Disable
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.TwoFactor.Disable"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Two factor authentication has been disabled.";
            }
        }

    }
}
