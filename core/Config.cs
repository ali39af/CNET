using System.Net;
using CNET;

public class Config
{
    public string ConfigPath { get; private set; }

    // [CNETConfig]
    public IPEndPoint ForwardDnsEndpoint { get; set; }
    public List<string> AllowedIPs { get; set; } = new List<string>();
    public bool CaptivatePortal { get; set; }
    public string CaptivatePortalDomain { get; set; }
    public string CaptivatePortalPanelDomain { get; set; }
    public string CaptivatePortalDefaultAdminUsername { get; set; }
    public string CaptivatePortalDefaultAdminPassword { get; set; }

    // [DNS]
    public IPEndPoint DnsBindEndpoint { get; set; }
    public IPAddress RouterIPV4 { get; set; }
    public IPAddress RouterIPV6 { get; set; }

    // [Router]
    public IPEndPoint HttpBindEndpoint { get; set; }
    public IPEndPoint HttpsBindEndpoint { get; set; }

    public Config(string path)
    {
        ConfigPath = path;

        if (File.Exists(ConfigPath))
        {
            LoadConfig();
        }
        else
        {
            ForwardDnsEndpoint = ParseEndpoint("8.8.8.8:53");
            AllowedIPs = new List<string> { "127.0.0.1/32", "127.0.0.2/32" };
            CaptivatePortal = true;
            CaptivatePortalDomain = "cnet.portal"; // We not related to "China National Environment Teams" CNET for us mean Clean Internet 
            CaptivatePortalPanelDomain = "cnet.panel";
            CaptivatePortalDefaultAdminUsername = "admin";
            CaptivatePortalDefaultAdminPassword = PasswordGenerator.CreateSecurePassword(12);
            DnsBindEndpoint = ParseEndpoint("127.0.0.1:53");
            RouterIPV4 = IPAddress.Parse("127.0.0.2");
            RouterIPV6 = IPAddress.Parse("::");
            HttpBindEndpoint = ParseEndpoint("127.0.0.2:80");
            HttpsBindEndpoint = ParseEndpoint("127.0.0.2:443");

            SaveConfig();
        }
    }

    public void LoadConfig()
    {
        try
        {
            string[] lines = File.ReadAllLines(ConfigPath);
            string section = "";

            foreach (var line in lines)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#"))
                    continue;

                if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                {
                    section = trimmed;
                    continue;
                }

                var parts = trimmed.Split('=', 2);
                if (parts.Length != 2) continue;

                string key = parts[0].Trim();
                string value = parts[1].Trim();

                switch (section)
                {
                    case "[CNETConfig]":
                        if (key == "forwardDnsEndpoint")
                            ForwardDnsEndpoint = ParseEndpoint(value);
                        else if (key == "allowedIPs")
                            AllowedIPs = new List<string>(value.Split(','));
                        else if (key == "captivatePortal")
                            CaptivatePortal = bool.TryParse(value, out var result) && result;
                        else if (key == "captivatePortalDomain")
                            CaptivatePortalDomain = value;
                        else if (key == "captivatePortalPanelDomain")
                            CaptivatePortalPanelDomain = value;
                        else if (key == "captivatePortalDefaultAdminUsername")
                            CaptivatePortalDefaultAdminUsername = value;
                        else if (key == "captivatePortalDefaultAdminPassword")
                            CaptivatePortalDefaultAdminPassword = value;
                        break;

                    case "[DNS]":
                        if (key == "dnsBindEndpoint")
                            DnsBindEndpoint = ParseEndpoint(value);
                        else if (key == "routerIPV4")
                            RouterIPV4 = IPAddress.Parse(value);
                        else if (key == "routerIPV6")
                            RouterIPV6 = IPAddress.Parse(value);
                        break;

                    case "[Router]":
                        if (key == "httpBindEndpoint")
                            HttpBindEndpoint = ParseEndpoint(value);
                        else if (key == "httpsBindEndpoint")
                            HttpsBindEndpoint = ParseEndpoint(value);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading config: {ex.Message}");
        }
    }

    public void SaveConfig()
    {
        try
        {
            using (StreamWriter writer = new StreamWriter(ConfigPath, false))
            {
                writer.WriteLine("[CNETConfig]");
                writer.WriteLine($"forwardDnsEndpoint={FormatEndpoint(ForwardDnsEndpoint)}");
                writer.WriteLine($"allowedIPs={string.Join(",", AllowedIPs)}");
                writer.WriteLine($"captivatePortal={CaptivatePortal.ToString().ToLower()}");
                writer.WriteLine($"captivatePortalDomain={CaptivatePortalDomain.ToLower()}");
                writer.WriteLine($"captivatePortalPanelDomain={CaptivatePortalPanelDomain.ToLower()}");
                writer.WriteLine($"captivatePortalDefaultAdminUsername={CaptivatePortalDefaultAdminUsername}");
                writer.WriteLine($"captivatePortalDefaultAdminPassword={CaptivatePortalDefaultAdminPassword}");
                writer.WriteLine();

                writer.WriteLine("[DNS]");
                writer.WriteLine($"dnsBindEndpoint={FormatEndpoint(DnsBindEndpoint)}");
                writer.WriteLine($"routerIPV4={RouterIPV4}");
                writer.WriteLine($"routerIPV6={RouterIPV6}");
                writer.WriteLine();

                writer.WriteLine("[Router]");
                writer.WriteLine($"httpBindEndpoint={FormatEndpoint(HttpBindEndpoint)}");
                writer.WriteLine($"httpsBindEndpoint={FormatEndpoint(HttpsBindEndpoint)}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error saving config: {ex.Message}");
        }
    }

    private IPEndPoint ParseEndpoint(string input)
    {
        try
        {
            var parts = input.Split(':');
            if (parts.Length < 2)
                throw new FormatException($"Invalid endpoint format: {input}");

            var ip = IPAddress.Parse(parts[0]);
            var port = int.Parse(parts[1]);
            return new IPEndPoint(ip, port);
        }
        catch
        {
            throw new FormatException($"Cannot parse endpoint: {input}");
        }
    }

    private string FormatEndpoint(IPEndPoint ep)
    {
        return $"{ep.Address}:{ep.Port}";
    }
}
