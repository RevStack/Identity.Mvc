using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web.Http;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity.Owin;
using RevStack.Mvc;

namespace RevStack.Identity.Mvc
{
    
    [Authorize]
    public class IdentityApiController<TUser,TRole,TUserManager,TRoleManager,TProfile,TKey> : ApiController
        where TUser : class, IIdentityUser<TKey>
        where TRole : class,IIdentityRole
        where TUserManager :ApplicationUserManager<TUser,TKey>
        where TRoleManager :ApplicationRoleManager<TRole>
        where TProfile :class,IProfileModel<TKey>
        where TKey:IEquatable<TKey>,IConvertible
    {
        #region "Private Ref"
        protected readonly IAuthenticationManager _authenticationManager;
        protected readonly Func<TUserManager> _userManagerFactory;
        protected readonly Func<TRoleManager> _roleManagerFactory;
        protected readonly Func<TUser> _applicationUserFactory;
        protected readonly Func<TRole> _applicationRoleFactory;

        #endregion

        #region "Constructor"
        public IdentityApiController( 
            IAuthenticationManager authenticationManager, 
            Func<TUserManager> userManagerFactory,
            Func<TRoleManager> roleManagerFactory,
            Func<TUser> applicationUserFactory,
            Func<TRole> applicationRoleFactory
            )
            
        {
            _authenticationManager = authenticationManager;
            _userManagerFactory = userManagerFactory;
            _roleManagerFactory = roleManagerFactory;
            _applicationUserFactory = applicationUserFactory;
            _applicationRoleFactory = applicationRoleFactory;
            
        }

        #endregion

        #region "Public"

        /// <summary>
        /// 
        /// </summary>
        public virtual bool ConfirmEmail
        {
            get
            {
                return Settings.Email.EnableConfirmation;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual string AuthenticationType
        {
            get
            {
                return DefaultAuthenticationTypes.ApplicationCookie;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("SignIn")]
        [AllowAnonymous]
        public virtual async Task<IHttpActionResult> SignIn(SignInModel model)
        {
            return await SignIn_Post(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("SignUp")]
        [AllowAnonymous]
        public virtual async Task<IHttpActionResult> SignUp(SignUpModel model)
        {
            return await SignUp_Post(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("UpdateProfile")]
        public virtual async Task<IHttpActionResult> UpdateProfile(TProfile model)
        {
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            var userManager = _userManagerFactory();
            var id = User.Identity.GetUserId<TKey>();
            var user = await userManager.FindByIdAsync(id);
            user = await user.CopyPropertiesFromAsync(model);
            await userManager.UpdateAsync(user);
            return Content(HttpStatusCode.OK, model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("SetPassword")]
        public virtual async Task<IHttpActionResult> SetPassword(SetPasswordModel model)
        {
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.AddPasswordAsync(User.Identity.GetUserId<TKey>(), model.NewPassword);
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                return Content(HttpStatusCode.OK, model);
            }
            else
            {
                var identityResponse = new IdentityResponse<SetPasswordModel>();
                identityResponse.Entity = model;
                identityResponse.Message = "Set Password Failed";
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ForgotPassword")]
        public virtual async Task<IHttpActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            var identityResponse = new IdentityResponse<ForgotPasswordModel>();
            var userManager = _userManagerFactory();
            var user = await userManager.FindByNameAsync(model.Email);
            if (user == null || !(await userManager.IsEmailConfirmedAsync(user.Id)))
            {
                identityResponse.Message = "Failed to find an available user for this request";
                identityResponse.Entity = model;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }

            /* Send an email with this link */
            var code = await userManager.GeneratePasswordResetTokenAsync(user.Id);
            var subject = Settings.ForgotPassword.Subject;
            var body = Settings.ForgotPassword.Body;
            var callbackUrl = Url.Link("Default", new { Controller = "Identity", Action = "ResetPassword", userId = user.Id, code });
            body += Environment.NewLine + "Please reset your password by clicking <a href=\"" + callbackUrl +
                    "\">here</a>";

            await userManager.SendEmailAsync(user.Id, subject, body);
            identityResponse.Message = "Redirect to Forgot Password Confirmation";
            identityResponse.Entity = model;
            identityResponse.ReturnUrl = Url.Link("Default", new { Controller = "Identity", Action = "ForgotPasswordConfirmation" });
            identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
            return Content(HttpStatusCode.RedirectMethod, identityResponse);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ChangePassword")]
        public virtual async Task<IHttpActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            var identityResponse = new IdentityResponse<ChangePasswordModel>();
            var userManager = _userManagerFactory();
            var id = User.Identity.GetUserId<TKey>();
            var result = await userManager.ChangePasswordAsync(id, model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(id);
                if (user != null)
                {
                    var userIdentity = await userManager.CreateIdentityAsync(user, AuthenticationType);
                    _authenticationManager.SignIn(userIdentity);
                }

                return Content(HttpStatusCode.OK, model);
            }
            else
            {
                identityResponse.Entity = model;
                identityResponse.Message = "Change Password Failed";
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ResetPassword")]
        public virtual async Task<IHttpActionResult> ResetPassword(ResetPasswordModel model)
        {

            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            var identityResponse = new IdentityResponse<ResetPasswordModel>();
            var userManager = _userManagerFactory();
            var user = await userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);

            }
            var result = await userManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return Content(HttpStatusCode.OK, model);
            }
            else
            {
                identityResponse.Entity = model;
                identityResponse.Message = result.Errors.FirstOrDefault();
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("AddPhoneNumber")]
        public virtual async Task<IHttpActionResult> AddPhoneNumber(AddPhoneNumberModel model)
        {
            var identityResponse = new IdentityResponse<AddPhoneNumberModel>();
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            // Generate the token and send it
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var code = await userManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId<TKey>(), model.Number);
            if (userManager.SmsService != null)
            {
                var message = new IdentityMessage
                {
                    Destination = model.Number,
                    Body = "Your security code is: " + code
                };
                await userManager.SmsService.SendAsync(message);
            }

            identityResponse.Entity = new AddPhoneNumberModel { Number = model.Number };
            identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
            identityResponse.Message = "Verify phone number";
            identityResponse.ReturnUrl= Url.Link("Default", new { Controller = "Identity", Action = "VerifyPhoneNumber"});
            return Content(HttpStatusCode.RedirectMethod, identityResponse);
            
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("VerifyPhoneNumber")]
        public virtual async Task<IHttpActionResult> VerifyPhoneNumber(VerifyPhoneNumberModel model)
        {
            var identityResponse = new IdentityResponse<VerifyPhoneNumberModel>();
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);
            // Generate the token and send it
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.ChangePhoneNumberAsync(User.Identity.GetUserId<TKey>(), model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                return Content(HttpStatusCode.OK, model);
            }
            else
            {
                identityResponse.Entity = model;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                identityResponse.Message = "Unable to verify phone";
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("RemovePhoneNumber")]
        public virtual async Task<IHttpActionResult> RemovePhoneNumber(RemovePhoneNumberModel model)
        {
            var identityResponse = new IdentityResponse<RemovePhoneNumberModel>();
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.SetPhoneNumberAsync(User.Identity.GetUserId<TKey>(), null);
            if (!result.Succeeded)
            {
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                identityResponse.Entity = model;
                identityResponse.Message = "Remove phone number failed";
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return Content(HttpStatusCode.OK, model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ManageLogins")]
        public virtual async Task<IHttpActionResult> ManageLogins(ManageLoginsModel model)
        {
            var identityResponse = new IdentityResponse<ManageLoginsModel>();
            var userManager = _userManagerFactory();
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user == null)
            {
                identityResponse.Message = "No user found";
                identityResponse.Entity = model;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
            var userLogins = await userManager.GetLoginsAsync(User.Identity.GetUserId<TKey>());
            var otherLogins = _authenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();

            model.CurrentLogins = userLogins;
            model.OtherLogins = otherLogins;
            return Content(HttpStatusCode.OK, model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("RemoveLogin")]
        public virtual async Task<IHttpActionResult> RemoveLogin(RemoveLoginModel model)
        {
            var identityResponse = new IdentityResponse<RemoveLoginModel>();
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.RemoveLoginAsync(User.Identity.GetUserId<TKey>(), new UserLoginInfo(model.LoginProvider, model.ProviderKey));
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                return Content(HttpStatusCode.OK, model);
            }
            else
            {
                identityResponse.Entity = model;
                identityResponse.Message = Settings.Manage.Error;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
            
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [Route("EnableTwoFactorAuthentication")]
        public virtual async Task<IHttpActionResult> EnableTwoFactorAuthentication()
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            await userManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId<TKey>(), true);
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return Content(HttpStatusCode.OK, true);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [Route("DisableTwoFactorAuthentication")]
        public virtual async Task<IHttpActionResult> DisableTwoFactorAuthentication()
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            await userManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId<TKey>(), false);
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return Content(HttpStatusCode.OK, true);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public virtual bool Equals(TKey other)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Assign available roles to user. Available roles are passed in the SignUp View Model Response
        /// </summary>
        /// <param name="roles"></param>
        /// <param name="user"></param>
        /// <param name="userManager"></param>
        /// <param name="roleManager"></param>
        /// <returns></returns>
        public virtual bool AssignRolesToUser(List<string> roles,TUser user,TUserManager userManager,TRoleManager roleManager)
        {
            bool status = true;
            if (roles.Count() < 1) return true;
            foreach(string role in roles)
            {
                if (roleManager.RoleExists(role))
                {
                    var result = userManager.AddToRole(user.Id, role);
                    if (!result.Succeeded) status = false;
                }
                else status = false;
            }

            return status;
        }
        #endregion

        #region "Protected"
        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        protected async Task<IHttpActionResult> SignIn_Post(SignInModel model)
        {
            var identityResponse = new IdentityResponse<SignInModel>();
            if (!ModelState.IsValid)
            {
                identityResponse.Message = "Invalid Model State";
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                identityResponse.Entity = model;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }

            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result =
                await
                    signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe,
                        Settings.Validation.UserLockoutEnabledByDefault);
            switch (result)
            {
                case SignInStatus.Success:
                    var currentUser = userManager.FindByEmail(model.Email);
                    return Content(HttpStatusCode.OK, model);
                case SignInStatus.LockedOut:
                    identityResponse.Message = "The account is currently locked";
                    identityResponse.StatusCode = HttpStatusCode.Forbidden;
                    identityResponse.Entity = model;
                    return Content(HttpStatusCode.Forbidden, identityResponse);
                case SignInStatus.RequiresVerification:
                    identityResponse.Message = "The acount requires verification";
                    identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
                    identityResponse.Entity = model;
                    identityResponse.ReturnUrl = Url.Link("Default", new { Controller = "Identity", Action = "SendCode" });
                    return Content(HttpStatusCode.RedirectMethod, identityResponse);
                case SignInStatus.Failure:
                default:
                    identityResponse.Message = "Invalid Login Account";
                    identityResponse.StatusCode = HttpStatusCode.Unauthorized;
                    identityResponse.Entity = model;
                    return Content(HttpStatusCode.Unauthorized, identityResponse);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        protected async Task<IHttpActionResult> SignUp_Post(SignUpModel model)
        {
            if (!ModelState.IsValid) return Content(HttpStatusCode.BadRequest, model);

            //init an identityReponse
            var identityResponse = new IdentityResponse<SignUpModel>();

            //instances from the respective factories
            var userManager = _userManagerFactory();
            var roleManager = _roleManagerFactory();
            var newUser = _applicationUserFactory();

            //if UserName is null, email is used as the username
            if (model.UserName == null)
            {
                //assign username,email=submitted email
                newUser.UserName = model.Email;
                newUser.Email = model.Email;
                //enforce unique username
                var existingUserByName = await userManager.FindByNameAsync(newUser.UserName);
                if (existingUserByName != null)
                {
                    identityResponse.Message = "User Name Already Exists";
                    identityResponse.Entity = model;
                    identityResponse.StatusCode = HttpStatusCode.BadRequest;
                    return Content(HttpStatusCode.BadRequest, identityResponse);
                }
            }
            else
            {
                //username & email distinctly assigned
                newUser.UserName = model.UserName;
                newUser.Email = model.Email;
                var existingUserByName = await userManager.FindByNameAsync(newUser.UserName);
                //enforce unique username
                if (existingUserByName != null)
                {
                    identityResponse.Message = "Username already exists";
                    identityResponse.Entity = model;
                    identityResponse.StatusCode = HttpStatusCode.BadRequest;
                    return Content(HttpStatusCode.BadRequest, identityResponse);
                }
                //if signup by username & RequireUniqueEmail set, force unique email
                if (Settings.Validation.RequireUniqueEmail)
                {
                    var existingUserByEmail = await userManager.FindByEmailAsync(model.Email);
                    if (existingUserByEmail != null)
                    {
                        identityResponse.Message = "Submitted email address already exists";
                        identityResponse.Entity = model;
                        identityResponse.StatusCode = HttpStatusCode.BadRequest;
                        return Content(HttpStatusCode.BadRequest, identityResponse);
                    }
                }
            }

            var result = await userManager.CreateAsync(newUser, model.Password);
            if (!result.Succeeded)
            {
                identityResponse.Message = result.Errors.FirstOrDefault();
                identityResponse.Entity = model;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);
            }
            bool assignRolesStatus = AssignRolesToUser(model.Roles, newUser, userManager, roleManager);

            //if role assignment fails, roll back the created user
            if (!assignRolesStatus)
            {
                userManager.Delete(newUser);
                identityResponse.Message = "Failed to create user because role assignment failed";
                identityResponse.Entity = model;
                identityResponse.StatusCode = HttpStatusCode.BadRequest;
                return Content(HttpStatusCode.BadRequest, identityResponse);

            }
            if (ConfirmEmail)
            {
                var subject = Settings.Email.Subject;
                var body = Settings.Email.Body;
                var code = await userManager.GenerateEmailConfirmationTokenAsync(newUser.Id);
                var callbackUrl = Url.Link("Default", new { Controller = "Identity", Action = "ConfirmEmail", userId = newUser.Id, code });
                body += Environment.NewLine + "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>";
                await userManager.SendEmailAsync(newUser.Id, subject, body);
                identityResponse.Message = "Email must be confirmed before sign-in";
                identityResponse.Entity = model;
                identityResponse.ReturnUrl = Url.Link("Default", new { Controller = "Identity", Action = "ConfirmEmailNotice" });
                identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
                return Content(HttpStatusCode.RedirectMethod, identityResponse);
            }
            else
            {
                //create the identity and sign-in
                var userIdentity = await userManager.CreateIdentityAsync(newUser, AuthenticationType);
                _authenticationManager.SignIn(userIdentity);
                return Content(HttpStatusCode.OK, model);
            }
        }
        #endregion
    }
}

