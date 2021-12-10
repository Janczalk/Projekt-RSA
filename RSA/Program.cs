using System;
using System.Security.Cryptography;
using System.IO;
using System.Xml.Serialization;
using System.Text;

namespace RSA
{
    class Program
    {
        public class RSAEncryption
        {
            private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
            private RSAParameters KluczPrywatny;
            private RSAParameters KluczPubliczny;
            
            //zdefiniowanie kluczy publicznych i prywatnych
            public RSAEncryption()
            {
                KluczPrywatny = csp.ExportParameters(true);
                KluczPubliczny = csp.ExportParameters(false);
            }

            //tworzenie klucza publicznego
            public string PobierzKluczPubliczny()
            {
                var sw = new StringWriter();
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, KluczPubliczny);
                return sw.ToString();
            }

            //funkcja odpowiedzialna za szyfrowanie tekstu
            public string Encrypt(string tekst)
            {
                csp = new RSACryptoServiceProvider();
                csp.ImportParameters(KluczPubliczny);
                var dane = Encoding.Unicode.GetBytes(tekst);
                var szyfrowanie = csp.Encrypt(dane, false);
                return Convert.ToBase64String(szyfrowanie);
            }

            //funkcja odpowiedzialna za odszyfrowaywanie tekstu
            public string Decrypt(string TekstZaszyfrowany)
            {
                var dane = Convert.FromBase64String(TekstZaszyfrowany);
                csp.ImportParameters(KluczPrywatny);
                var tekst = csp.Decrypt(dane, false);
                return Encoding.Unicode.GetString(tekst);
            }
        }

        static void Main(string[] args)
        {
            RSAEncryption rsa = new RSAEncryption();
            string szyfr = string.Empty;

            // wyświetla klucz publiczny od nowej linii
            Console.WriteLine($"Klucz publiczny to: {rsa.PobierzKluczPubliczny()} \n");

            //prosi o podanie tekstu do zaszyfrowania
            Console.WriteLine("Podaj ponizej tekst do zaszyfrownia: ");
            var tekst = Console.ReadLine();

            Console.WriteLine("");
            
            //jezeli wprowadzone dane nie sa puste wykonaj zaszyfrowanie tekstu
            if(!string.IsNullOrEmpty(tekst))
            {
                szyfr = rsa.Encrypt(tekst);
                Console.WriteLine($"Zaszyfrowany tekst: {szyfr}");
            }

            //odszyfrowywanie wczesniejszego tekstu
            Console.WriteLine("Nacisnij dowolny klawisz (tylko nie od zasilania komputera ani alt+f4) aby odszyfrowac tekst");
            Console.ReadLine();
            Console.WriteLine("");
            var odszyfrowanyTekst = rsa.Decrypt(szyfr);
            Console.WriteLine($"Odszyfrowany tekst: {odszyfrowanyTekst}");
            Console.ReadKey();
        }
    }
}
