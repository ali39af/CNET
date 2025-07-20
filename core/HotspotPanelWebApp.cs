using System.Text.Json;
using System.Text;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;

namespace CNET
{
    public class HotspotPanelWebApp : WebApp
    {
        private static readonly Dictionary<string, string> resourceMap = new()
        {
            { "Management", "CNET.wwwroot.Management.html" },
        };

        static HotspotPanelWebApp()
        {
            LoadEmbeddedResources(typeof(HotspotPanelWebApp), resourceMap);
        }

        public override WebAppResponse OnNewRequest(WebAppRequest request)
        {
            using AppDbContext db = new();

            var auth = request.Headers.TryGetValue("Auth", out var authHeader) ? authHeader : null;

            if (request.Path == "/login" && request.Method == "POST")
            {
                var credentials = JsonSerializer.Deserialize<LoginRequest>(request.Body);

                if (credentials == null)
                {
                    return new WebAppResponse
                    {
                        StatusCode = "400 Bad Request",
                        Headers = { { "Content-Type", "plain/text" } }
                    };
                }

                bool isValid = Hasher.Sha512(config.CaptivatePortalDefaultAdminPassword) == credentials.Password && config.CaptivatePortalDefaultAdminUsername == credentials.Username;

                return new WebAppResponse
                {
                    StatusCode = isValid ? "200 OK" : "401 Unauthorized",
                    Headers = { { "Content-Type", "plain/text" } }
                };
            }

            if (request.Path == "/users")
            {
                if (auth != Hasher.Sha512(config.CaptivatePortalDefaultAdminPassword))
                {
                    return new WebAppResponse
                    {
                        StatusCode = "403 Forbidden",
                        Headers = { { "Content-Type", "plain/text" } }
                    };
                }

                switch (request.Method)
                {
                    case "GET":
                        var users = db.HotspotUsers.ToList().Select(u => new
                        {
                            u.Id,
                            u.Username,
                            Status = CacheDatabase.Instance.ContainsLogin(u.Username) ? "online" : "offline",
                            u.DataInBytes,
                            u.DataOutBytes
                        });

                        return new WebAppResponse
                        {
                            StatusCode = "200 OK",
                            Headers = { { "Content-Type", "application/json" } },
                            Body = JsonSerializer.Serialize(users)
                        };

                    case "POST":
                        var newUser = JsonSerializer.Deserialize<HotspotUser>(request.Body);
                        if (newUser != null)
                        {
                            db.HotspotUsers.Add(newUser);
                            db.SaveChanges();
                            return new WebAppResponse
                            {
                                StatusCode = "200 OK",
                                Headers = { { "Content-Type", "plain/text" } }
                            };
                        }
                        break;

                    case "DELETE":
                        if (int.TryParse(request.Body, out var deleteId))
                        {
                            var userToRemove = db.HotspotUsers.FirstOrDefault(u => u.Id == deleteId);
                            if (userToRemove != null)
                            {
                                CacheDatabase.Instance.RemoveLogin(userToRemove.Username);
                                db.HotspotUsers.Remove(userToRemove);
                                db.SaveChanges();
                                return new WebAppResponse
                                {
                                    StatusCode = "200 OK",
                                    Headers = { { "Content-Type", "plain/text" } }
                                };
                            }
                        }
                        break;
                }

                return new WebAppResponse
                {
                    StatusCode = "400 Bad Request",
                    Headers = { { "Content-Type", "plain/text" } }
                };
            }

            return new WebAppResponse
            {
                StatusCode = "200 OK",
                Headers = { { "Content-Type", "text/html" } },
                Body = GetResourceContent(typeof(HotspotPanelWebApp), "Management")
            };
        }
        private class LoginRequest
        {
            public required string Username { get; set; }
            public required string Password { get; set; }
        }
    }

}
