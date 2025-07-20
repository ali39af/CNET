using System.Text.RegularExpressions;

namespace CNET
{
    public static class WildcardMatcher
    {
        public static bool IsMatch(string pattern, string input)
        {
            if (pattern == "*")
                return true;

            string regexPattern = WildcardToRegex(pattern);
            return Regex.IsMatch(input, regexPattern, RegexOptions.IgnoreCase);
        }

        private static string WildcardToRegex(string pattern)
        {
            return "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
        }
    }
}
