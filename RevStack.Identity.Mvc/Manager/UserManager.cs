using System;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;

namespace RevStack.Identity.Mvc
{
   
    public class ApplicationUserManager<TUser, TKey> : UserManager<TUser, TKey>
        where TUser : class, IIdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        
        public ApplicationUserManager(IIdentityUserStore<TUser, TKey> store,
            IIdentityEmailService emailService,
            IIdentitySmsService smsService,
            IDataProtectionProvider dataProtectionProvider

            ) : base(store) {

            //Set Email,Sms Identity Services
            EmailService = emailService;
            SmsService = smsService;

            // Configure validation logic for usernames
            UserValidator = new UserValidator<TUser,TKey>(this)
            {
                AllowOnlyAlphanumericUserNames = Settings.Validation.AllowOnlyAlphanumericUserNames,
                RequireUniqueEmail = Settings.Validation.RequireUniqueEmail
            };

            // Configure validation logic for passwords
            PasswordValidator = new PasswordValidator
            {
                RequiredLength = Settings.Validation.MinimumPasswordLength,
                RequireNonLetterOrDigit = Settings.Validation.RequireNonLetterOrDigit,
                RequireDigit = Settings.Validation.RequireDigit,
                RequireLowercase = Settings.Validation.RequireLowercase,
                RequireUppercase = Settings.Validation.RequireUppercase
            };

            // Configure user lockout defaults
            UserLockoutEnabledByDefault = Settings.Validation.UserLockoutEnabledByDefault;
            DefaultAccountLockoutTimeSpan =Settings.Validation.DefaultAccountLockoutTimeSpan;
            MaxFailedAccessAttemptsBeforeLockout =Settings.Validation.MaxFailedAccessAttemptsBeforeLockout;

            //Two-factor Authentication Providers
            RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<TUser,TKey>
            {
                MessageFormat = "Your security code is {0}"
            });

            RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<TUser,TKey>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });

            ///Data Protection Provider has to be set to send user tokens
            var dataProtector = dataProtectionProvider.Create(Settings.Configuration.Identifier);
            UserTokenProvider = new DataProtectorTokenProvider<TUser,TKey>(dataProtector);


            //alternatively use this if you are running in Azure Web Sites
            if (Settings.Configuration.IsAzureHosted)
            {
                UserTokenProvider = new EmailTokenProvider<TUser,TKey>();
            }
        }

    }


}
