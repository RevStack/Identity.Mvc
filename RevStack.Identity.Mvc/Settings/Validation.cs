using System;
using System.Configuration;

namespace RevStack.Identity.Mvc.Settings
{
    public static class Validation
    {
        public static bool AllowOnlyAlphanumericUserNames
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.AllowOnlyAlphanumericUserNames"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireUniqueEmail
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireUniqueEmail"];
                if (result != null) return Convert.ToBoolean(result);
                return true;
            }
        }
        public static int MinimumPasswordLength
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.MinimumPasswordLength"];
                if (result != null) return Convert.ToInt32(result);
                return 8;
            }
        }
        public static bool RequireNonLetterOrDigit
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireNonLetterOrDigit"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireDigit
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireDigit"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireLowercase
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireLowercase"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireUppercase
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireUppercase"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool UserLockoutEnabledByDefault
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.UserLockoutEnabledByDefault"];
                if (result != null) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static TimeSpan DefaultAccountLockoutTimeSpan
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.DefaultAccountLockoutTimeSpan"];
                if (result != null) return TimeSpan.FromMinutes(Convert.ToInt32(result));
                return TimeSpan.FromMinutes(30);
            }
        }
        public static int MaxFailedAccessAttemptsBeforeLockout
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.MaxFailedAccessAttemptsBeforeLockout"];
                if (result != null) return Convert.ToInt32(result);
                return 5;
            }
        }

    }
}
