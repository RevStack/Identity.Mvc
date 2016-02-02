using System;
using Microsoft.AspNet.Identity;

namespace RevStack.Identity.Mvc
{
    public class ApplicationRoleManager<TRole> : RoleManager<TRole>
        where TRole : class, IIdentityRole
    {
        public ApplicationRoleManager(IIdentityRoleStore<TRole> store):base(store)
        {
            
        }

    }
}
