using System;
using System.Threading.Tasks;
using System.Web.Mvc;
using System.Linq;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity.Owin;

namespace RevStack.Identity.Mvc
{
    [Authorize]
    public class IdentityController<TUser, TRole, TUserManager,TRoleManager, TProfile, TKey> :Controller
        where TUser : class, IIdentityUser<TKey>
        where TRole : class, IIdentityRole
        where TUserManager : ApplicationUserManager<TUser, TKey>
        where TRoleManager : ApplicationRoleManager<TRole>
        where TProfile : class, IProfileModel<TKey>
        where TKey : IEquatable<TKey>,IConvertible
    {

        #region "Constants"
        protected const string IDENTITY_CONTROLLER = "Identity";
        protected const string HOME_CONTROLLER = "Home";

        private const string INDEX_VIEW = "Index";
        private const string ERROR_VIEW = "Error";
        private const string EXTERNAL_LOGIN_ERROR_VIEW = "ExternalLoginError";
        private const string EXTERNAL_LOGIN_FAILURE_VIEW = "ExternalLoginFailure";
        private const string LOCKOUT_VIEW = "Lockout";
        private const string VERIFY_CODE_VIEW = "VerifyCode";
        private const string SEND_CODE_VIEW = "SendCode";
        private const string EXTERNAL_LOGIN_CONFIRMATION_VIEW = "ExternalLoginConfirmation";
        private const string RESET_PASSWORD_VIEW = "ResetPassword";
        private const string SET_PASSWORD_VIEW = "SetPassword";
        private const string CHANGE_PASSWORD_VIEW = "ChangePassword";
        private const string FORGOT_PASSWORD_VIEW = "ForgotPassword";
        private const string FORGOT_PASSWORD_CONFIRMATION_VIEW = "ForgotPasswordConfirmation";
        private const string CONFIRM_EMAIL_NOTICE_VIEW = "ConfirmEmailNotice";
        private const string CONFIRM_EMAIL_VIEW = "ConfirmEmail";
        private const string ADD_PHONENUMBER_VIEW = "AddPhoneNumber";
        private const string VERIFY_PHONENUMBER_VIEW = "VerifyPhoneNumber";
        private const string MANAGE_LOGINS_VIEW = "ManageLogins";

        private const string INDEX_ACTION = "Index";
        private const string RESET_PASSWORD_ACTION = "ResetPassword";
        private const string FORGOT_PASSWORD_CONFIRMATION_ACTION = "ForgotPasswordConfirmation";
        private const string RESET_PASSWORD_CONFIRMATION_ACTION = "ResetPasswordConfirmation";
        private const string VERIFY_CODE_ACTION = "VerifyCode";
        private const string SEND_CODE_ACTION = "SendCode";
        private const string EXTERNAL_LOGIN_CALLBACK_ACTION = "ExternalLoginCallback";
        private const string LOGIN_ACTION = "Sign-In";
        private const string VERIFY_PHONENUMBER_ACTION = "VerifyPhoneNumber";
        private const string LINK_LOGIN_CALLBACK_ACTION = "LinkLoginCallback";
        private const string MANAGE_LOGINS_ACTION = "ManageLogins";

        protected readonly IAuthenticationManager _authenticationManager;
        protected readonly Func<TUserManager> _userManagerFactory;
        protected readonly Func<TRoleManager> _roleManagerFactory;
        protected readonly Func<TUser> _applicationUserFactory;
        protected readonly Func<TRole> _applicationRoleFactory;

        #endregion

        #region "Constructor"
        public IdentityController(
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

        #region "ConfirmEmail"
        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        /* GET: /Identity/ConfirmEmail */
        public virtual async Task<ActionResult> ConfirmEmail(TKey userId, string code)
        {
            return await ConfirmEmail_Get(userId, code);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /* GET: /Identity/ConfirmEmailNotice */
        [AllowAnonymous]
        public virtual ActionResult ConfirmEmailNotice()
        {
            return ConfirmEmailNotice_Get();
        }

        #endregion

        #region "Password"
        /// <summary>
        ///  GET ForgotPassword
        /// </summary>
        /// <returns></returns>
        /* GET: /Identity/ForgotPassword */
        [AllowAnonymous]
        public virtual ActionResult ForgotPassword()
        {
            return ForgotPassword_Get();
        }

        
        /// <summary>
        /// POST ForgotPassword
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /* POST: /Identity/ForgotPassword */
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var userManager = _userManagerFactory();
                var user = await userManager.FindByNameAsync(model.Email);
                if (user == null || !(await userManager.IsEmailConfirmedAsync(user.Id)))
                {

                    return View(ERROR_VIEW);
                }

                /* Send an email with this link */
                var code = await userManager.GeneratePasswordResetTokenAsync(user.Id);
                var subject = Settings.ForgotPassword.Subject;
                var body = Settings.ForgotPassword.Body;
                var callbackUrl = Url.Action(RESET_PASSWORD_ACTION, IDENTITY_CONTROLLER, new { userId = user.Id, code }, Request.Url.Scheme);
                body += Environment.NewLine + "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>";
                await userManager.SendEmailAsync(user.Id, subject, body);
                return RedirectToAction(FORGOT_PASSWORD_CONFIRMATION_ACTION, IDENTITY_CONTROLLER);
            }

            /* If we got this far, something failed, redisplay form */
            return View(model);
        }

        /// <summary>
        ///  GET ForgotPasswordConfirmation
        /// </summary>
        /// <returns></returns>
        /* GET: /Identity/ForgotPasswordConfirmation */
        [AllowAnonymous]
        public virtual ActionResult ForgotPasswordConfirmation()
        {
            return ForgotPasswordConfirmation_Get();
        }


        /// <summary>
        ///  GET ResetPassword
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        /* GET: /Identity/ResetPassword */
        [AllowAnonymous]
        public virtual ActionResult ResetPassword(string code)
        {
            return ResetPassword_Get(code);
        }

        /// <summary>
        ///  POST ResetPassword
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /* POST: /Identity/ResetPassword */
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var userManager = _userManagerFactory();
            var user = await userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                /* Don't reveal that the user does not exist */
                return RedirectToAction(RESET_PASSWORD_CONFIRMATION_ACTION, IDENTITY_CONTROLLER);
            }
            var result = await userManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(RESET_PASSWORD_CONFIRMATION_ACTION, IDENTITY_CONTROLLER);
            }
            else
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }
                return View();
            }
            
        }

        /// <summary>
        ///  GET ChangePassword
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/ChangePassword
        public virtual ActionResult ChangePassword()
        {
            return ChangePassword_Get();
        }


        /// <summary>
        ///  POST ChangePassword
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        // POST: /Identity/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.ChangePasswordAsync(User.Identity.GetUserId<TKey>(), model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                return RedirectToAction(INDEX_ACTION, Settings.ChangePassword.Success );
            }
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
            return View(model);
        }

        /// <summary>
        /// GET SetPassword
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/SetPassword
        public ActionResult SetPassword()
        {
            return SetPassword_Get();
        }

        /// <summary>
        /// POST SetPassword
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        // POST: /Identity/SetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(SetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
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
                    return RedirectToAction(INDEX_ACTION, Settings.SetPassword.Success);
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        #endregion

        #region "Two-Factor Authentication"
        /// <summary>
        ///  GET SendCode
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <param name="rememberMe"></param>
        /// <returns></returns>
        /* GET: /Identity/SendCode */
        [AllowAnonymous]
        public virtual async Task<ActionResult> SendCode(string returnUrl, bool rememberMe)
        {
            return await SendCode_Get(returnUrl, rememberMe);
        }

        /// <summary>
        /// POST SendCode
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /* POST: /Identity/SendCode */
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> SendCode(SendCodeModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(ERROR_VIEW);
            }
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            /* Generate the token and send it */
            if (!await signInManager.SendTwoFactorCodeAsync(model.Provider))
            {
                return View(ERROR_VIEW);
            }
            return RedirectToAction(VERIFY_CODE_ACTION,
                new { Provider = model.Provider, model.ReturnUrl, model.RememberMe });
        }

        /// <summary>
        ///  GET VerifyCode
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="returnUrl"></param>
        /// <param name="rememberMe"></param>
        /// <returns></returns>
        /* GET: /Identity/VerifyCode */
        [AllowAnonymous]
        public virtual async Task<ActionResult> VerifyCode(string provider, string returnUrl, bool rememberMe)
        {
            return await VerifyCode_Get(provider, returnUrl, rememberMe);
        }

        /// <summary>
        ///  POST VerifyCode
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /* POST: /Identity/VerifyCode */
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> VerifyCode(VerifyCodeModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            // The following code protects for brute force attacks against the two factor codes. 
            // If a user enters incorrect codes for a specified amount of time then the user account 
            // will be locked out for a specified amount of time. 
            // You can configure the account lockout settings in web.config
            var result = await signInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent: model.RememberMe, rememberBrowser: model.RememberBrowser);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(model.ReturnUrl);
                case SignInStatus.LockedOut:
                    return View(LOCKOUT_VIEW);
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid code.");
                    return View(VERIFY_CODE_VIEW, model);
            }
        }

        /// <summary>
        /// POST EnableTwoFactorAuthentication
        /// </summary>
        /// <returns></returns>
        // POST: /Identity/EnableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            await userManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId<TKey>(), true);
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return RedirectToAction(INDEX_ACTION, IDENTITY_CONTROLLER);
        }

        /// <summary>
        ///  POST DisableTwoFactorAuthentication
        /// </summary>
        /// <returns></returns>
        // POST: /Identity/DisableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            await userManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId<TKey>(),false);
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return RedirectToAction(INDEX_ACTION, IDENTITY_CONTROLLER);
        }

        /// <summary>
        ///  GET AddPhoneNumber
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/AddPhoneNumber
        public ActionResult AddPhoneNumber()
        {
            return AddPhoneNumber_Get();
        }

        /// <summary>
        ///  POST AddPhoneNumber
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        // POST: /Identity/AddPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
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
            return RedirectToAction(VERIFY_PHONENUMBER_ACTION, new { PhoneNumber = model.Number });
        }

        /// <summary>
        ///  GET VerifyPhoneNumber
        /// </summary>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        // GET: /Identity/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            return await VerifyPhoneNumber_Get(phoneNumber);
        }

        /// <summary>
        ///  POST VerifyPhoneNumber
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        // POST: /Identity/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
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
                return RedirectToAction(INDEX_ACTION, Settings.PhoneNumber.AddSuccess );
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Failed to verify phone");
            return View(model);
        }


        /// <summary>
        ///  GET RemovePhoneNumber
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/RemovePhoneNumber
        public virtual async Task<ActionResult> RemovePhoneNumber()
        {
            return await RemovePhoneNumber_Get();
        }



        #endregion

        #region "OAuth"

        /// <summary>
        /// 
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        /* POST: /Identity/ExternalLogin */
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public virtual ActionResult ExternalLogin(string provider, string returnUrl)
        {
            /* Request a redirect to the external login provider */
            if (provider == null)
            {
                RedirectToAction(EXTERNAL_LOGIN_ERROR_VIEW);
            }
            return new ChallengeResult(provider,
                Url.Action(EXTERNAL_LOGIN_CALLBACK_ACTION, IDENTITY_CONTROLLER, new { ReturnUrl = returnUrl }));
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        // GET: /Identity/ExternalLoginCallback
        [AllowAnonymous]
        public virtual async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            return await ExternalLoginCallback_Get(returnUrl);
        }

        // POST: /Identity/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public virtual async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction(INDEX_ACTION, IDENTITY_CONTROLLER);
            }

            if (ModelState.IsValid)
            {
                var userManager = _userManagerFactory();
                var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
                // Get the information about the user from the external login provider
                var info = await _authenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View(EXTERNAL_LOGIN_FAILURE_VIEW);
                }
                //var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var user = _applicationUserFactory();
                user.UserName = model.Email;
                user.Email = model.Email;

                var result = await userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await userManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                        return RedirectToLocal(returnUrl);
                    }
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error);
                }
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        /// <summary>
        /// GET ManageLogins
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/ManageLogins
        public virtual async Task<ActionResult> ManageLogins(string message)
        {
            return await ManageLogins_Get(message);
        }

        /// <summary>
        /// POST LinkLogin
        /// </summary>
        /// <param name="provider"></param>
        /// <returns></returns>
        // POST: /Identity/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new ChallengeResult(provider, Url.Action(LINK_LOGIN_CALLBACK_ACTION, IDENTITY_CONTROLLER), User.Identity.GetUserId(),Settings.XsrfKey.Key);
        }

        /// <summary>
        /// GET LinkLoginCallback
        /// </summary>
        /// <returns></returns>
        // GET: /Identity/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            return await LinkLoginCallback_Get();
        }

        /// <summary>
        ///  POST RemoveLogin
        /// </summary>
        /// <param name="loginProvider"></param>
        /// <param name="providerKey"></param>
        /// <returns></returns>
        // POST: /Identity/RemoveLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            string message = "";
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.RemoveLoginAsync(User.Identity.GetUserId<TKey>(), new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
                if (user != null)
                {
                    await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
                }
                message = Settings.RemoveLogin.Success;
            }
            else
            {
                message = Settings.Manage.Error;
            }
            return RedirectToAction(MANAGE_LOGINS_ACTION, message);
        }

        #endregion

        #region "Index"
        /// <summary>
        /// GET Index
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        /// GET: /Identity/Index
        public async Task<ActionResult> Index(string message)
        {
            return await Index_Get(message);
        }
        #endregion




        #region "Protected"

        /// <summary>
        /// 
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> Index_Get(string message)
        {
            ViewBag.StatusMessage = message;
            var userManager = _userManagerFactory();
            var userId = User.Identity.GetUserId<TKey>();
            var model = new IdentityManageModel
            {
                HasPassword = HasPassword(userManager),
                PhoneNumber = await userManager.GetPhoneNumberAsync(userId),
                TwoFactor = await userManager.GetTwoFactorEnabledAsync(userId),
                Logins = await userManager.GetLoginsAsync(userId),
                BrowserRemembered = await _authenticationManager.TwoFactorBrowserRememberedAsync(User.Identity.GetUserId())
            };

            return View(INDEX_VIEW,model);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> LinkLoginCallback_Get()
        {
            var loginInfo = await _authenticationManager.GetExternalLoginInfoAsync(Settings.XsrfKey.Key, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction(MANAGE_LOGINS_ACTION, Settings.Manage.Error);
            }
            var userManager = _userManagerFactory();
            var result = await userManager.AddLoginAsync(User.Identity.GetUserId<TKey>(), loginInfo.Login);
            return result.Succeeded ? RedirectToAction(MANAGE_LOGINS_ACTION) : RedirectToAction(MANAGE_LOGINS_ACTION, Settings.Manage.Error );
        }



        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> ManageLogins_Get(string message)
        {
            ViewBag.StatusMessage = message;
            var userManager = _userManagerFactory();
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user == null)
            {
                return View(ERROR_VIEW);
            }
            var userLogins = await userManager.GetLoginsAsync(User.Identity.GetUserId<TKey>());
            var otherLogins = _authenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();
            ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
            return View(MANAGE_LOGINS_VIEW, new ManageLoginsModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }


        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult SetPassword_Get()
        {
            return View(SET_PASSWORD_VIEW);
        }


        /// <summary>
        /// 
        /// </summary>
        ///
        [NonAction]
        protected ActionResult ChangePassword_Get()
        {
            return View(CHANGE_PASSWORD_VIEW);
        }



        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        ///
        [NonAction]
        protected async Task<ActionResult> RemovePhoneNumber_Get()
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await userManager.SetPhoneNumberAsync(User.Identity.GetUserId<TKey>(), null);
            if (!result.Succeeded)
            {
                return RedirectToAction(INDEX_ACTION, Settings.Manage.Error);
            }
            var user = await userManager.FindByIdAsync(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                await signInManager.SignInAsync(user, isPersistent: Settings.Login.Persistence, rememberBrowser: Settings.Login.Persistence);
            }
            return RedirectToAction(INDEX_ACTION, Settings.PhoneNumber.RemoveSuccess );
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> VerifyPhoneNumber_Get(string phoneNumber)
        {
            var userManager = _userManagerFactory();
            var code = await userManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId<TKey>(), phoneNumber);
            // Send an SMS through the SMS provider to verify the phone number
            return phoneNumber == null ? View(ERROR_VIEW) : View(VERIFY_PHONENUMBER_VIEW,new VerifyPhoneNumberModel { PhoneNumber = phoneNumber });
        }


        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult AddPhoneNumber_Get()
        {
            return View(ADD_PHONENUMBER_VIEW);
        }

        /// <summary>
        ///  GET ConfirmEmail
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="code"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> ConfirmEmail_Get(TKey userId, string code)
        {
            if (string.IsNullOrEmpty(userId.ToString()) || string.IsNullOrEmpty(code))
            {
                return View(ERROR_VIEW);
            }
            else
            {
                var userManager = _userManagerFactory();
                var result = await userManager.ConfirmEmailAsync(userId, code);
                return View(result.Succeeded ? CONFIRM_EMAIL_VIEW : ERROR_VIEW);
            }

        }

        /// <summary>
        ///  GET ConfirmEmailNotice
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult ConfirmEmailNotice_Get()
        {
            if (Request.Cookies[Settings.Email.Cookie] == null)
            {
                return View(ERROR_VIEW);
            }
            else
            {
                Request.Cookies[Settings.Email.Cookie].Expires = DateTime.Now.AddDays(-1);
                return View(CONFIRM_EMAIL_NOTICE_VIEW);
            }
        }

        /// <summary>
        ///  GET ForgotPassword
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult ForgotPassword_Get()
        {
            return View(FORGOT_PASSWORD_VIEW, new ForgotPasswordModel());
        }

        /// <summary>
        ///  GET ForgotPasswordConfirmation
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult ForgotPasswordConfirmation_Get()
        {
            return View(FORGOT_PASSWORD_CONFIRMATION_VIEW);
        }

        /// <summary>
        ///  GET ResetPassword
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        [NonAction]
        protected ActionResult ResetPassword_Get(string code)
        {
            return code == null ? View(ERROR_VIEW) : View(RESET_PASSWORD_VIEW);
        }

        /// <summary>
        ///  GET SendCode
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <param name="rememberMe"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> SendCode_Get(string returnUrl, bool rememberMe)
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var userId = await signInManager.GetVerifiedUserIdAsync();
            if (userId == null)
            {
                return View(ERROR_VIEW);
            }
            var userFactors = await userManager.GetValidTwoFactorProvidersAsync(userId);
            var factorOptions =
                userFactors.Select(purpose => new SelectListItem { Text = purpose, Value = purpose }).ToList();
            return
                View(SEND_CODE_VIEW, new SendCodeModel { Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }



        /// <summary>
        ///  GET VerifyCode
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="returnUrl"></param>
        /// <param name="rememberMe"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> VerifyCode_Get(string provider, string returnUrl, bool rememberMe)
        {
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            /* Require that the user has already logged in via username/password or external login */
            if (!await signInManager.HasBeenVerifiedAsync())
            {
                return View(ERROR_VIEW);
            }
            var user = await userManager.FindByIdAsync(await signInManager.GetVerifiedUserIdAsync());
            if (user != null)
            {
                var code = await userManager.GenerateTwoFactorTokenAsync(user.Id, provider);
            }
            return View(VERIFY_CODE_VIEW, new VerifyCodeModel { Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe });
        }

       
        /// <summary>
        ///  GET ExternalLoginCallback
        /// </summary>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [NonAction]
        protected async Task<ActionResult> ExternalLoginCallback_Get(string returnUrl)
        {
            var loginInfo = await _authenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction(LOGIN_ACTION);
            }

            // Sign in the user with this external login provider if the user already has a login
            var userManager = _userManagerFactory();
            var signInManager = new SignInManager<TUser, TKey>(userManager, _authenticationManager);
            var result = await signInManager.ExternalSignInAsync(loginInfo, isPersistent: Settings.Login.Persistence);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                case SignInStatus.LockedOut:
                    return View(LOCKOUT_VIEW);
                case SignInStatus.RequiresVerification:
                    return RedirectToAction(SEND_CODE_ACTION, new { ReturnUrl = returnUrl, RememberMe = Settings.Login.Persistence });
                case SignInStatus.Failure:
                default:
                    // If the user does not have an account, then prompt the user to create an account
                    ViewBag.ReturnUrl = returnUrl;
                    ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                    return View(EXTERNAL_LOGIN_CONFIRMATION_VIEW, new ExternalLoginConfirmationModel { Email = loginInfo.Email });
            }
        }

        /// <summary>
        /// GET SignOut
        /// </summary>
        /// <returns></returns>
        [NonAction]
        protected ActionResult SignOut_Get()
        {
            _authenticationManager.SignOut();
            return RedirectToAction(INDEX_ACTION, HOME_CONTROLLER);
        }
      
        #endregion


        #region "Private"
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction(INDEX_ACTION, HOME_CONTROLLER);
        }

        private bool HasPassword(TUserManager userManager)
        {
            var user = userManager.FindById(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        private bool HasPhoneNumber(TUserManager userManager)
        {
            var user = userManager.FindById(User.Identity.GetUserId<TKey>());
            if (user != null)
            {
                return user.PhoneNumber != null;
            }
            return false;
        }

        #endregion
    }
}
