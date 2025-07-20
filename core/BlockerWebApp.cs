using System.Net;

namespace CNET
{
    public class BlockerWebApp : WebApp
    {
        private static readonly Dictionary<string, string> resourceMap = new()
        {
            { "ADS", "CNET.wwwroot.ADS.html" },
            { "NSFW", "CNET.wwwroot.NSFW.html" },
            { "SCAM", "CNET.wwwroot.SCAM.html" },
        };

        private readonly DomainType _type;

        static BlockerWebApp()
        {
            LoadEmbeddedResources(typeof(BlockerWebApp), resourceMap);
        }

        public BlockerWebApp(DomainType type)
        {
            _type = type;
        }

        public override WebAppResponse OnNewRequest(WebAppRequest request)
        {
            string status = "403 Forbidden";
            string body = _type switch
            {
                DomainType.Ads => GetResourceContent(typeof(BlockerWebApp), "ADS"),
                DomainType.NSFW => GetResourceContent(typeof(BlockerWebApp), "NSFW"),
                DomainType.Scam => GetResourceContent(typeof(BlockerWebApp), "SCAM"),
                _ => string.Empty
            };

            if (string.IsNullOrEmpty(body))
                status = "500 Internal Server Error";

            if (request.Path == "/ignore" && request.Method == "POST")
            {
                IPEndPoint? remoteEndPoint = request.ClientConnection.Client.RemoteEndPoint as IPEndPoint;
                if (remoteEndPoint != null)
                {
                    CacheDatabase.Instance.AddIgnore(request.Headers["Host"].Trim().ToLower(), remoteEndPoint.Address);
                }
                return new WebAppResponse
                {
                    StatusCode = "200 OK",
                };
            }

            return new WebAppResponse
            {
                StatusCode = status,
                Headers = { { "Content-Type", "text/html" } },
                Body = body
            };
        }
    }
}
