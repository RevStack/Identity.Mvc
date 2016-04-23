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
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireUniqueEmail
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireUniqueEmail"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return true;
            }
        }
        public static int MinimumPasswordLength
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.MinimumPasswordLength"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToInt32(result);
                return 6;
            }
        }
        public static bool RequireNonLetterOrDigit
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireNonLetterOrDigit"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireDigit
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireDigit"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireLowercase
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireLowercase"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool RequireUppercase
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.RequireUppercase"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static bool UserLockoutEnabledByDefault
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.UserLockoutEnabledByDefault"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToBoolean(result);
                return false;
            }
        }
        public static TimeSpan DefaultAccountLockoutTimeSpan
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.DefaultAccountLockoutTimeSpan"];
                if (!string.IsNullOrEmpty(result)) return TimeSpan.FromMinutes(Convert.ToInt32(result));
                return TimeSpan.FromMinutes(30);
            }
        }
        public static int MaxFailedAccessAttemptsBeforeLockout
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.Validation.MaxFailedAccessAttemptsBeforeLockout"];
                if (!string.IsNullOrEmpty(result)) return Convert.ToInt32(result);
                return 5;
            }
        }

    }
}
