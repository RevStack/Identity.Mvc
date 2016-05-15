using System;
using RevStack.Identity;

namespace RevStack.Identity.Mvc
{
    public class ApplicationBaseUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Street { get; set; }
        public string ZipCode { get; set; }
        
        public ApplicationBaseUser() : base() { }
       
    }
}