using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.ModelBinding;

namespace RevStack.Identity.Mvc
{
    public class ContentErrorResult : IHttpActionResult
    {
        private HttpRequestMessage _request;
        private HttpStatusCode _statusCode;
        private string _errorMessage;
        public ContentErrorResult(HttpRequestMessage request, string errorMessage)
        {
            _request = request;
            _statusCode = HttpStatusCode.BadRequest;
            _errorMessage = errorMessage;
        }
        public ContentErrorResult(HttpRequestMessage request,HttpStatusCode statusCode, string errorMessage)
        {
            _request = request;
            _statusCode = statusCode;
            _errorMessage = errorMessage;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var msg = _request.CreateErrorResponse(_statusCode, new HttpError(_errorMessage));
            return Task.FromResult(msg);
        }
    }

    public class ModelErrorResult : IHttpActionResult
    {
        private HttpRequestMessage _request;
        private HttpStatusCode _statusCode;
        private IEnumerable<ModelError> _errors;
        public ModelErrorResult(HttpRequestMessage request,IEnumerable<ModelError> errors)
        {
            _request = request;
            _errors = errors;
            _statusCode = HttpStatusCode.BadRequest;
        }
        public ModelErrorResult(HttpRequestMessage request, IEnumerable<ModelError> errors,HttpStatusCode statusCode)
        {
            _request = request;
            _errors = errors;
            _statusCode = statusCode;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var errorMessage = _errors.Select(x => x.ErrorMessage).FirstOrDefault();
            var msg = _request.CreateErrorResponse(_statusCode, new HttpError(errorMessage));
            return Task.FromResult(msg);
        }
    }

    public class ContentRedirectResult<T> : IHttpActionResult where T : class
    {
        private HttpRequestMessage _request;
        private HttpStatusCode _statusCode;
        private string _url;
        private string _header = "X-Location";
        private T _value = null;
        public ContentRedirectResult(HttpRequestMessage request, string url, T value)
        {
            _request = request;
            _statusCode = HttpStatusCode.RedirectMethod;
            _url = url;
            _value = value;
        }
        public ContentRedirectResult(HttpRequestMessage request, HttpStatusCode statusCode, string url, T value)
        {
            _request = request;
            _statusCode = statusCode;
            _url = url;
            _value = value;
        }
        public ContentRedirectResult(HttpRequestMessage request, string url, string header, T value)
        {
            _request = request;
            _statusCode = HttpStatusCode.RedirectMethod;
            _url = url;
            _value = value;
        }
        public ContentRedirectResult(HttpRequestMessage request, HttpStatusCode statusCode, string url,string header, T value)
        {
            _request = request;
            _statusCode = statusCode;
            _url = url;
            _value = value;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var msg=_request.CreateResponse(_statusCode, _value);
            msg.Headers.Add(_header, _url);

            return Task.FromResult(msg);
        }

    }

    public class ContentRedirectResult : IHttpActionResult
    {
        private HttpRequestMessage _request;
        private HttpStatusCode _statusCode;
        private string _url;
        private string _header = "X-Location";
        public ContentRedirectResult(HttpRequestMessage request, string url)
        {
            _request = request;
            _statusCode = HttpStatusCode.RedirectMethod;
            _url = url;
        }
        public ContentRedirectResult(HttpRequestMessage request, HttpStatusCode statusCode, string url)
        {
            _request = request;
            _statusCode = statusCode;
            _url = url;
        }
        public ContentRedirectResult(HttpRequestMessage request, string url, string header)
        {
            _request = request;
            _statusCode = HttpStatusCode.RedirectMethod;
            _url = url;
            _header = header;
        }
        public ContentRedirectResult(HttpRequestMessage request, HttpStatusCode statusCode, string url,string header)
        {
            _request = request;
            _statusCode = statusCode;
            _url = url;
            _header = header;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            var msg=_request.CreateResponse(_statusCode);
            msg.Headers.Add(_header, _url);

            return Task.FromResult(msg);
        }

    }
}
