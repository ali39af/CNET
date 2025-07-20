using System.Text;

namespace CNET
{
    public static class PasswordGenerator
    {
        public static string CreateSecurePassword(int length)
        {
            const string allowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*";
            StringBuilder generatedPassword = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < length; i++)
            {
                int randomIndex = random.Next(allowedCharacters.Length);
                generatedPassword.Append(allowedCharacters[randomIndex]);
            }

            return generatedPassword.ToString();
        }
    }
}
