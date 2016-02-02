using System;
using RevStack.Pattern;

namespace RevStack.Identity.Mvc
{
    public interface IAuthenticationModel : IEntity<string>
    {
        bool SignedIn { get; set; }
    }

    public class AuthenticationModel : IAuthenticationModel
    {
        public string Id { get; set; }
        public bool SignedIn { get; set; }
    }
}
