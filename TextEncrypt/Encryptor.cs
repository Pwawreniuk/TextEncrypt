using System.Runtime.InteropServices;
using System.Text;
using MySql.Data.MySqlClient;

public class Encryptor
{
    [DllImport("RSA.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void EncryptRSA(byte[] input, int inputLength, byte[] output, int outputLength, byte[] key, int keyLength);

    static void Main()
    {
        Console.WriteLine("Please, enter text for encryption:");
        string input = Console.ReadLine();
        // If the message is too long, cut it to 200 characters
        if (input.Length > 200)
        {
            input = input.Substring(0, 200);
        }
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        byte[] outputBytes = new byte[256];
        byte[] key = new byte[2048];

        EncryptRSA(inputBytes, inputBytes.Length, outputBytes, outputBytes.Length, key, key.Length);


        // Define connection string
        string connString = "Server=localhost;Database=Encrypted_data;User ID=root;Password=admin;";
        SaveEncryptedData(connString, outputBytes, key);
    }

    public static void SaveEncryptedData(string connString, byte[] data, byte[] key)
    {
        using MySqlConnection mConnection = new MySqlConnection(connString);
        try
        {
            mConnection.Open();

            // SQL command to insert data
            string query = "INSERT INTO Encrypted (encrypted_text, pkey) VALUES (@Data, @Key)";

            using MySqlCommand mCommand = new MySqlCommand(query, mConnection);
            mCommand.Parameters.Add("@Data", MySqlDbType.Blob).Value = data;
            mCommand.Parameters.Add("@Key", MySqlDbType.Blob).Value = key;
            mCommand.ExecuteNonQuery();
            Console.WriteLine("\nData inserted successfully.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }
}
