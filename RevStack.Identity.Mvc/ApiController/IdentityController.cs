using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web.Http;
using System.Threading.Tasks;
using System.Web.Http.ModelBinding;
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
                return Settings.ConfirmEmail.Enable;
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
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
            var userManager = _userManagerFactory();
            var id = User.Identity.GetUserId<TKey>();
            var user = await userManager.FindByIdAsync(id);
            user = await user.CopyPropertiesFromAsync(model);
            await userManager.UpdateAsync(user);
            return Ok(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("SetPassword")]
        public virtual async Task<IHttpActionResult> SetPassword(SetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.AddPasswordAsync(User.Identity.GetUserId<TKey>(), model.Password);
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                return Ok(model);
            }
            else
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ForgotPassword")]
        [AllowAnonymous]
        public virtual async Task<IHttpActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
            var identityResponse = new IdentityResponse();
            var userManager = _userManagerFactory();
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return new ContentErrorResult(Request, HttpStatusCode.NotFound, Settings.User.NotFound);
            }

            /* Send an email with this link */
            var code = await userManager.GeneratePasswordResetTokenAsync(user.Id);
            var subject = Settings.ForgotPassword.Subject;
            string body = "Dear " + model.Email + ":";
            body += Settings.Email.NewLine + Settings.Email.NewLine;
            body += Settings.ForgotPassword.Body;
            var callbackUrl = Url.Link("Default", new { Controller = "Identity", Action = "ResetPassword", userId = user.Id, code });
            body += Settings.Email.NewLine + "Please reset your password by clicking <a href=\"" + callbackUrl +
                    "\">here</a>";

            body += Settings.Email.NewLine + Settings.Email.NewLine;
            body += Settings.Email.Valediction;

            await userManager.SendEmailAsync(user.Id, subject, body);

            identityResponse.Message = "Redirect to Forgot Password Confirmation";
            identityResponse.Location = Url.Link("Default", new { Controller = "Identity", Action = "ForgotPasswordConfirmation" });
            identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
            return new ContentRedirectResult<IdentityResponse>(Request, identityResponse.Location, identityResponse);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ChangePassword")]
        public virtual async Task<IHttpActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
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

                return Ok(model);
            }
            else
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ResetPassword")]
        [AllowAnonymous]
        public virtual async Task<IHttpActionResult> ResetPassword(ResetPasswordModel model)
        {

            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
           
            var userManager = _userManagerFactory();
            var user = await userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                return new ContentErrorResult(Request, HttpStatusCode.NotFound, Settings.User.NotFound);
            }
            var result = await userManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return Ok(model);
            }
            else
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
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
            var identityResponse = new IdentityResponse();
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
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

            identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
            identityResponse.Message = "Verify phone number";
            identityResponse.Location= Url.Link("Default", new { Controller = "Identity", Action = "VerifyPhoneNumber"});
            return new ContentRedirectResult<IdentityResponse>(Request, identityResponse.Location, identityResponse);
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
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }
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
                return Ok(model);
            }
            else
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
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
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
            }
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return Ok(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("ManageLogins")]
        public virtual async Task<IHttpActionResult> ManageLogins(ManageLoginsModel model)
        {
            var userManager = _userManagerFactory();
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user == null)
            {
                return new ContentErrorResult(Request, HttpStatusCode.NotFound, Settings.User.NotFound);
            }
            var userLogins = await userManager.GetLoginsAsync(User.Identity.GetUserId<TKey>());
            var otherLogins = _authenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();

            model.CurrentLogins = userLogins;
            model.OtherLogins = otherLogins;
            return Ok(model);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [Route("RemoveLogin")]
        public virtual async Task<IHttpActionResult> RemoveLogin(RemoveLoginModel model)
        {
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
                return Ok(model);
            }
            else
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
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
            return Ok();
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
            return Ok();
        }

        [Route("IdentityUser")]
        [AllowAnonymous]
        public virtual async Task<IHttpActionResult> IdentityUser()
        {
            var model = new IdentityUserModel
            {
                Id=null,
                Authenticated=false,
                Email=null
            };

            if (User.Identity.IsAuthenticated)
            {
                var userName = User.Identity.GetUserName();
                var userManager = _userManagerFactory();
                var user = await userManager.FindByNameAsync(userName);
                model.Id = user.Id.ToString();
                model.Authenticated = true;
                model.Email = user.Email;
                model.Name = user.UserName;
                model.Roles = userManager.GetRoles(user.Id).ToList();
            }

            return Ok(model);
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
            var identityResponse = new IdentityResponse();
            if (!ModelState.IsValid)
            {
                var modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
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
                    return Ok(model);
                case SignInStatus.LockedOut:
                    return new ContentErrorResult(Request, HttpStatusCode.Forbidden, Settings.User.Locked);
                case SignInStatus.RequiresVerification:
                    identityResponse.Message = "The acount requires verification";
                    identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
                    identityResponse.Location = Url.Link("Default", new { Controller = "Identity", Action = "SendCode" });
                    return new ContentRedirectResult<IdentityResponse>(Request, identityResponse.Location, identityResponse);
                case SignInStatus.Failure:
                default:
                    return new ContentErrorResult(Request, HttpStatusCode.Forbidden, Settings.User.InvalidLogin);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        protected async Task<IHttpActionResult> SignUp_Post(SignUpModel model)
        {
            IEnumerable<ModelError> modelErrors;
            if (!ModelState.IsValid)
            {
                modelErrors = ModelState.Values.SelectMany(x => x.Errors);
                return new ModelErrorResult(Request, modelErrors);
            }

            //init an identityReponse
            var identityResponse = new IdentityResponse();

            //instances from the respective factories
            var userManager = _userManagerFactory();
            var roleManager = _roleManagerFactory();
            var newUser = _applicationUserFactory();
            newUser.SignUpDate = DateTime.Now;

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
                    return new ContentErrorResult(Request,Settings.User.Duplicate);
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
                    return new ContentErrorResult(Request, Settings.User.Duplicate);
                }
                //if signup by username & RequireUniqueEmail set, force unique email
                if (Settings.Validation.RequireUniqueEmail)
                {
                    var existingUserByEmail = await userManager.FindByEmailAsync(model.Email);
                    if (existingUserByEmail != null)
                    {
                        return new ContentErrorResult(Request, Settings.Email.Duplicate);
                    }
                }
            }

            var result = await userManager.CreateAsync(newUser, model.Password);
            if (!result.Succeeded)
            {
                return new ContentErrorResult(Request, result.Errors.FirstOrDefault());
            }
            bool assignRolesStatus = AssignRolesToUser(model.Roles, newUser, userManager, roleManager);

            //if role assignment fails, roll back the created user
            if (!assignRolesStatus)
            {
                userManager.Delete(newUser);
                return new ContentErrorResult(Request, "Failed to create user because role assignment failed");
            }

            if (ConfirmEmail)
            {
                var subject = Settings.ConfirmEmail.Subject;
                string body = "Dear " + model.Email + ":";
                body += Settings.Email.NewLine + Settings.Email.NewLine;
                body += Settings.ConfirmEmail.Body;

                var code = await userManager.GenerateEmailConfirmationTokenAsync(newUser.Id);
                var callbackUrl = Url.Link("Default", new { Controller = "Identity", Action = "ConfirmEmail", userId = newUser.Id, code });
                body += Settings.Email.NewLine + "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>";

                body += Settings.Email.NewLine + Settings.Email.NewLine;
                body += Settings.Email.Valediction;

                await userManager.SendEmailAsync(newUser.Id, subject, body);

                identityResponse.Message = "Email must be confirmed before sign-in";
                identityResponse.Location = Url.Link("Default", new { Controller = "Identity", Action = "ConfirmEmailNotice" });
                identityResponse.StatusCode = HttpStatusCode.RedirectMethod;
                return new ContentRedirectResult<IdentityResponse>(Request, identityResponse.Location, identityResponse);
            }
            else
            {
                //create the identity and sign-in
                var userIdentity = await userManager.CreateIdentityAsync(newUser, AuthenticationType);
                _authenticationManager.SignIn(userIdentity);
                return Ok(model);
            }
        }
        #endregion
    }
}

