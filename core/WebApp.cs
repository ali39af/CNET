using System.Net.Sockets;
using System.Reflection;
using System.Text;

namespace CNET
{
    public class WebAppRequest
    {
        public string Method { get; set; }
        public string Path { get; set; }
        public string HttpVersion { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public string Body { get; set; }
        public TcpClient ClientConnection;
    }

    public class WebAppResponse
    {
        public string StatusCode { get; set; } = "200 OK";
        public Dictionary<string, string> Headers { get; set; } = new();
        public string Body { get; set; } = "";

        public override string ToString()
        {
            StringBuilder sb = new();
            sb.AppendLine($"HTTP/1.1 {StatusCode}");
            foreach (KeyValuePair<string, string> header in Headers)
            {
                sb.AppendLine($"{header.Key}: {header.Value}");
            }
            sb.AppendLine();
            sb.Append(Body);
            return sb.ToString();
        }
    }

    public abstract class WebApp
    {
        private static readonly Dictionary<Type, Dictionary<string, string>> resourceStore = new();
        public Config config;

        protected static void LoadEmbeddedResources(Type type, Dictionary<string, string> resourceMap)
        {
            if (resourceStore.ContainsKey(type))
                return;

            Dictionary<string, string> contents = new();
            Assembly assembly = Assembly.GetExecutingAssembly();

            foreach (KeyValuePair<string, string> kvp in resourceMap)
            {
                using Stream? stream = assembly.GetManifestResourceStream(kvp.Value);
                if (stream == null)
                {
                    contents[kvp.Key] = string.Empty;
                }
                else
                {
                    using StreamReader reader = new(stream);
                    contents[kvp.Key] = reader.ReadToEnd();
                }
            }

            resourceStore[type] = contents;
        }

        protected static string GetResourceContent(Type type, string key)
        {
            if (resourceStore.TryGetValue(type, out Dictionary<string, string>? map) && map.TryGetValue(key, out string? content))
                return content;

            return string.Empty;
        }

        public void ProcessRequest(byte[] initialData, StreamReader reader, StreamWriter writer, TcpClient client)
        {
            try
            {
                string requestLine = Encoding.ASCII.GetString(initialData);
                int endOfLine = requestLine.IndexOf("\r\n");
                if (endOfLine == -1)
                {
                    SendErrorResponse(writer, 400, "Bad Request");
                    return;
                }

                requestLine = requestLine.Substring(0, endOfLine);
                string[] requestParts = requestLine.Split(' ');
                if (requestParts.Length != 3)
                {
                    SendErrorResponse(writer, 400, "Bad Request");
                    return;
                }

                WebAppRequest request = new()
                {
                    Method = requestParts[0],
                    Path = requestParts[1],
                    HttpVersion = requestParts[2],
                    ClientConnection = client
                };

                string line;
                int contentLength = 0;
                while (!string.IsNullOrEmpty(line = reader.ReadLine()))
                {
                    int separatorIndex = line.IndexOf(':');
                    if (separatorIndex >= 0)
                    {
                        string key = line.Substring(0, separatorIndex).Trim();
                        string value = line.Substring(separatorIndex + 1).Trim();
                        request.Headers[key] = value;

                        if (key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                        {
                            int.TryParse(value, out contentLength);
                        }
                    }
                }

                if (contentLength > 0)
                {
                    char[] bodyBuffer = new char[contentLength];
                    int bytesRead = 0;
                    while (bytesRead < contentLength)
                    {
                        int read = reader.Read(bodyBuffer, bytesRead, contentLength - bytesRead);
                        if (read == 0) break;
                        bytesRead += read;
                    }
                    request.Body = new string(bodyBuffer, 0, bytesRead);
                }

                WebAppResponse response = OnNewRequest(request);

                if (!response.Headers.ContainsKey("Content-Type"))
                {
                    response.Headers["Content-Type"] = "text/plain";
                }
                if (!response.Headers.ContainsKey("Content-Length"))
                {
                    response.Headers["Content-Length"] = Encoding.UTF8.GetByteCount(response.Body).ToString();
                }

                writer.Write(response.ToString());
                writer.Flush();
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine($"Internal Server Error: {e}");
#endif
                SendErrorResponse(writer, 500, "Internal Server Error");
            }
        }

        private void SendErrorResponse(StreamWriter writer, int statusCode, string statusMessage)
        {
            try
            {
                WebAppResponse errorResponse = new()
                {
                    StatusCode = $"{statusCode} {statusMessage}",
                    Body = $"{statusCode} {statusMessage}"
                };
                errorResponse.Headers["Content-Type"] = "text/plain";
                errorResponse.Headers["Content-Length"] = Encoding.UTF8.GetByteCount(errorResponse.Body).ToString();

                writer.Write(errorResponse.ToString());
                writer.Flush();
            }
            catch (Exception e)
            {
#if DEBUG
                Console.WriteLine($"Error sending error response: {e}");
#endif
            }
        }

        public abstract WebAppResponse OnNewRequest(WebAppRequest request);
    }
}