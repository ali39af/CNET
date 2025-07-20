using System.Net;
using System.Text.Json;

namespace CNET
{
    public class HotspotPortalWebApp : WebApp
    {
        private static readonly Dictionary<string, string> resourceMap = new()
        {
            { "Login", "CNET.wwwroot.Login.html" },
        };

        static HotspotPortalWebApp()
        {
            LoadEmbeddedResources(typeof(HotspotPortalWebApp), resourceMap);
        }

        public override WebAppResponse OnNewRequest(WebAppRequest request)
        {
            if (request.Path == "/login" && request.Method == "POST")
            {
                var credentials = JsonSerializer.Deserialize<LoginRequest>(request.Body);

                if (credentials == null)
                {
                    return new WebAppResponse
                    {
                        StatusCode = "400 Bad Request",
                        Headers = { { "Content-Type", "text/html" } },
                    };
                }

                using (AppDbContext dbContext = new())
                {
                    HotspotUser? user = dbContext.HotspotUsers.FirstOrDefault(u =>
                        u.Username == credentials.Username && u.Password == credentials.Password);

                    if (user != null)
                    {
                        IPEndPoint? remoteEndPoint = request.ClientConnection.Client.RemoteEndPoint as IPEndPoint;
                        if (remoteEndPoint != null)
                        {
                            CacheDatabase.Instance.SetLogin(credentials.Username, remoteEndPoint.Address);
                        }

                        return new WebAppResponse
                        {
                            StatusCode = "200 OK",
                            Headers = { { "Content-Type", "text/html" } },
                        };
                    }
                    else
                    {
                        return new WebAppResponse
                        {
                            StatusCode = "401 Unauthorized",
                            Headers = { { "Content-Type", "text/html" } },
                        };
                    }
                }
            }

            return new WebAppResponse
            {
                StatusCode = "200 OK",
                Headers = { { "Content-Type", "text/html" } },
                Body = GetResourceContent(typeof(HotspotPortalWebApp), "Login")
            };
        }

        private class LoginRequest
        {
            public required string Username { get; set; }
            public required string Password { get; set; }
        }

    }
}