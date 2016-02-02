using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace RevStack.Identity.Mvc
{
    public class SmsService : IIdentitySmsService
    {
        public string Id
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public Task SendAsync(IdentityMessage message)
        {
            throw new NotImplementedException();
        }
    }
}
