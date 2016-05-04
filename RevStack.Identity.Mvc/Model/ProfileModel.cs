using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;


namespace RevStack.Identity.Mvc
{
    public class ProfileModel : IProfileModel<string>
    {
        public string Id { get; set; }
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        [Required]
        public string Email { get; set; }
        public string Street { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string ZipCode { get; set; }
        public string PhoneNumber { get; set; }
        public DateTime SignUpDate { get; set; }
        public List<string> Roles { get; set; }

        public ProfileModel()
        {
            Roles = new List<string>();
        }
    }
}
