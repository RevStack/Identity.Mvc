﻿using System;
using System.Configuration;


namespace RevStack.Identity.Mvc.Settings
{
    public static class RemoveLogin
    {
        public static string Success
        {
            get
            {
                var result = ConfigurationManager.AppSettings["Identity.RemoveLogin.Success"];
                if (!string.IsNullOrEmpty(result)) return result;
                return "The social media login has been removed.";
            }
        }
    }
}
