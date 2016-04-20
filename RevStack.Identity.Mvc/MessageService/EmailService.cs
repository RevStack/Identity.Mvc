using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using System.Net;
using RevStack.Net;

namespace RevStack.Identity.Mvc
{
    public class EmailService : IIdentityEmailService
    {
        private string _id;
        private string _host;
        private string _user;
        private string _password;
        private string _from;
        public EmailService(string id,string host,string user,string password,string from)
        {
            _id = id;
            _host = host;
            _user = user;
            _password = password;
            _from = from;
        }

        public string Id
        {
            get
            {
                return _id;
            }
        }

        public Task SendAsync(IdentityMessage message)
        {
            var credentials = new NetworkCredential(_user, _password);
            Smtp.SendMail(message.Destination, _from, message.Subject, message.Body, false, _host, credentials);
            return Task.FromResult(0);
        }

        public Task SendAsync(IdentityMessage message,string sender)
        {
            var credentials = new NetworkCredential(_user, _password);
            Smtp.SendMail(message.Destination,sender, message.Subject, message.Body, false, _host, credentials);
            return Task.FromResult(0);
        }

        public Task SendAsync(IdentityMessage message, bool isHTML)
        {
            var credentials = new NetworkCredential(_user, _password);
            Smtp.SendMail(message.Destination, _from, message.Subject, message.Body, isHTML, _host, credentials);
            return Task.FromResult(0);
        }

        public Task SendAsync(IdentityMessage message, string sender, bool isHTML)
        {
            var credentials = new NetworkCredential(_user, _password);
            Smtp.SendMail(message.Destination, sender, message.Subject, message.Body, isHTML, _host, credentials);
            return Task.FromResult(0);
        }
    }
}
