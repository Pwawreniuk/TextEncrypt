using System.Runtime.InteropServices;
using System.Text;
using MySql.Data.MySqlClient;


class Decryptor
{
    [DllImport("RSA.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void DecryptRSA(byte[] input, int inputLength, byte[] key, byte[] output, int outputLength);

    static void Main()
    {
        string connectionString = "Server=localhost;Database=Encrypted_data;User ID=root;Password=admin;";
        // Check number of messages saved in the database and decrypt them all
        int messagesCount = CheckMessages(connectionString);
        for (int i = 1; i < messagesCount + 1; i++)
        {
            (byte[] retrievedData, byte[] pkey) = RetriveData(connectionString, i);
            byte[] decryptedData = new byte[retrievedData.Length];
            if (retrievedData == null)
            {
                Console.WriteLine("No data found.");
            }
            DecryptRSA(retrievedData, retrievedData.Length, pkey, decryptedData, decryptedData.Length);

            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine("\nDecrypted message " + i + ": " + decryptedText);
        }
    }

    static int CheckMessages(string connString)
    {
        int messages_count = 0;
        using MySqlConnection mConnection = new(connString);
        try
        {
            mConnection.Open();

            // SQL command to select data
            string query = "SELECT count(*) as mcount FROM encrypted";
            using MySqlCommand mCommand = new(query, mConnection);

            //Execute query and read number of messages
            using MySqlDataReader reader = mCommand.ExecuteReader();
            if (reader.Read())
            {
                messages_count = (int)(System.Int64)reader["mcount"];
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
        return messages_count;
    }

    static (byte[], byte[]) RetriveData(string connString, int id)
    {
        byte[] data = null;
        byte[] pkey = null;
        using MySqlConnection mConnection = new(connString);
        try
        {
            mConnection.Open();

            // SQL command to select data
            string query = "SELECT encrypted_text, pkey FROM Encrypted WHERE id=@Id";
            using MySqlCommand mCommand = new(query, mConnection);

            mCommand.Parameters.AddWithValue("@id", id);
            //Execute query and retrieve the data
            using MySqlDataReader reader = mCommand.ExecuteReader();
            if (reader.Read())
            {
                data = (byte[])reader["encrypted_text"];
                pkey = (byte[])reader["pkey"];
            }

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }

        return (data, pkey);
    }
}
