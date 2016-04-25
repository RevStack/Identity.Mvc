using System;
using RevStack.Pattern;

namespace RevStack.Identity.Mvc
{
    public interface IProfileModel<TKey> : IEntity<TKey>
    {
        string FirstName { get; set; }
        string LastName { get; set; }
        string Email { get; set; }
        string Street { get; set; }
        string City { get; set; }
        string State { get; set; }
        string ZipCode { get; set; }
        string Phone { get; set; }
        DateTime SignUpDate { get; set; }
    }
}
