using System;
using System.Web;
using System.Web.Mvc;

using Microsoft.Owin.Security;

namespace RevStack.Identity.Mvc
{
    public class ChallengeResult : HttpUnauthorizedResult
    {

        public ChallengeResult(string provider, string redirectUri)
            : this(provider, redirectUri, null, null)
        {
        }

        public ChallengeResult(string provider, string redirectUri, string userId, string xsrfKey)
        {
            LoginProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
            XsrfKey = xsrfKey;
        }

        public string LoginProvider { get; set; }
        public string RedirectUri { get; set; }
        public string UserId { get; set; }
        public string XsrfKey { get; set; }

        public override void ExecuteResult(ControllerContext context)
        {
            var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }

            context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);

        }
    }

}
