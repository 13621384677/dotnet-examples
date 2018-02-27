namespace Mazonesoft.Examples
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    internal class Program
    {
        private const string PFX_PASSWORD = "123456";

        private static readonly DirectoryInfo ResourceDirectory =
            new DirectoryInfo(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources"));

        private static readonly FileInfo CertificateFile =
            new FileInfo(Path.Combine(ResourceDirectory.FullName, "ssl.cer"));

        private static readonly FileInfo PfxCertificateFile =
            new FileInfo(@"D:\Git\my.github.com\dotnet-examples\src\X509CertificateExample.Generator\bin\Debug\CA.pfx");

        private static void Main(string[] args)
        {
            var pfxCert = GetPfxFormatterCertificateFile();
            var privateKey = pfxCert.PrivateKey.ToXmlString(true);
            var cert = GetCertificateFile();
            var publicKey = cert.PublicKey.Key.ToXmlString(false);

            // Microsoft .NET Framework 出于安全考虑，仅提供 RSA 公钥解密。
            var encryptor = new RSACryptoServiceProvider();
            encryptor.FromXmlString(publicKey);
            var buffer = Encoding.UTF8.GetBytes(PFX_PASSWORD);
            buffer = encryptor.Encrypt(buffer, false);

            var decryptor = new RSACryptoServiceProvider();
            decryptor.FromXmlString(privateKey);
            buffer = decryptor.Decrypt(buffer, false);

            Console.WriteLine(Encoding.UTF8.GetString(buffer));
            Console.Read();
        }

        /// <summary>
        ///     从 PFX 格式的文件中获取 <see cref="X509Certificate2"/> 类型的对象实例。
        /// </summary>
        /// <returns>
        ///     <para><see cref="X509Certificate2"/> 类型的对象实例。</para>
        ///     <para>X509 证书信息。</para>
        /// </returns>
        private static X509Certificate2 GetPfxFormatterCertificateFile()
        {
            if (!PfxCertificateFile.Exists)
                throw new FileNotFoundException("未能找到有效的 PFX 密钥文件。", PfxCertificateFile.FullName);
            return new X509Certificate2(PfxCertificateFile.FullName, PFX_PASSWORD, X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        ///     从 CER 格式的文件中获取 <see cref="X509Certificate2"/> 类型的对象实例。
        /// </summary>
        /// <returns>
        ///     <para><see cref="X509Certificate2"/> 类型的对象实例。</para>
        ///     <para>X509 证书信息。</para>
        /// </returns>
        private static X509Certificate2 GetCertificateFile()
        {
            if (!CertificateFile.Exists)
                throw new FileNotFoundException("未能找到有效的 CER 密钥文件。", CertificateFile.FullName);
            return new X509Certificate2(CertificateFile.FullName);
        }
    }
}