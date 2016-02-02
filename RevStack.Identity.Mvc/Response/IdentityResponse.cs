﻿using System;
using System.Net;

namespace RevStack.Identity.Mvc
{
    public class IdentityResponse<T>
    {
        public HttpStatusCode StatusCode { get; set; }
        public string Message { get; set; }
        public T Entity { get; set; }
        public string ReturnUrl { get; set; }
    }
}
