using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class SetPassword
    {
        public static string Success
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.SetPassword.Success"];
                if (result != null) return result;
                return "Your password has been set.";
            }
        }
    }
}
