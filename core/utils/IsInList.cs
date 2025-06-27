using System.Text.RegularExpressions;

namespace CNET
{
    public static class IsInList
    {
        public static bool Exist(HashSet<string> list, string domain)
        {
            foreach (var pattern in list)
            {
                if (pattern == "*") return true;
                string regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
                if (Regex.IsMatch(domain, regex, RegexOptions.IgnoreCase))
                    return true;
            }
            return false;
        }
    }
}