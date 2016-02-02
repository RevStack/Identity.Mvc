using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class Manage
    {
        public static string Error
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Manage.Error"];
                if (result != null) return result;
                return "An error has occurred.";
            }
        }
    }
}
