using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class ChangePassword
    {
        public static string Success
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.ChangePassword.Success"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "Your password has been changed.";
            }
        }
    }
}
