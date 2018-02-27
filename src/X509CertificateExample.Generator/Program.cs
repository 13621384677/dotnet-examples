namespace Mazonesoft.Examples
{
    using System;
    using System.Collections;
    using System.IO;

    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;

    class Program
    {
        static void Main(string[] args)
        {
            char[] passwd = "123456".ToCharArray();   //pfx密码  
            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            RsaKeyGenerationParameters genPar = new RsaKeyGenerationParameters(
                BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 25);
            keyGen.Init(genPar);
            AsymmetricCipherKeyPair keypair = keyGen.GenerateKeyPair();
            RsaKeyParameters pubKey = (RsaKeyParameters)keypair.Public; //CA公钥  
            RsaKeyParameters priKey = (RsaKeyParameters)keypair.Private;    //CA私钥  
            Hashtable attrs = new Hashtable();
            ArrayList order = new ArrayList();
            attrs.Add(X509Name.C, "CN");    //country code  
                                            //attrs.Add(X509Name.ST, "Guangdong province");   //province name  
                                            //attrs.Add(X509Name.L, "Guangzhou city");    //locality name        
            attrs.Add(X509Name.O, "South China Normal University"); //organization  
            attrs.Add(X509Name.OU, "South China Normal University");    //organizational unit name              
            attrs.Add(X509Name.CN, "CAcert");   //common name  
            attrs.Add(X509Name.E, "popozhude@qq.com");
            order.Add(X509Name.C);
            //order.Add(X509Name.ST);  
            //order.Add(X509Name.L);  
            order.Add(X509Name.O);
            order.Add(X509Name.OU);
            order.Add(X509Name.CN);
            order.Add(X509Name.E);
            X509Name issuerDN = new X509Name(order, attrs);
            X509Name subjectDN = issuerDN;  //自签证书，两者一样  
            X509V1CertificateGenerator v1certGen = new X509V1CertificateGenerator();
            v1certGen.SetSerialNumber(new BigInteger(128, new Random()));   //128位  
            v1certGen.SetIssuerDN(issuerDN);
            v1certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            v1certGen.SetNotAfter(DateTime.UtcNow.AddDays(365));
            v1certGen.SetSubjectDN(subjectDN);
            v1certGen.SetPublicKey(pubKey); //公钥  
            v1certGen.SetSignatureAlgorithm("SHA1WithRSAEncryption");
            Org.BouncyCastle.X509.X509Certificate CAcert = v1certGen.Generate(priKey);
            CAcert.CheckValidity();
            CAcert.Verify(pubKey);

            //属性包  
            /* 
            Hashtable bagAttr = new Hashtable(); 
            bagAttr.Add(PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Id, 
                new DerBmpString("CA's Primary Certificate")); 
            bagAttr.Add(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Id, 
                new SubjectKeyIdentifierStructure(pubKey)); 

            X509CertificateEntry certEntry = new X509CertificateEntry(CAcert,bagAttr); 
            */
            X509CertificateEntry certEntry = new X509CertificateEntry(CAcert);
            
            Pkcs12Store store = new Pkcs12StoreBuilder().Build();
            store.SetCertificateEntry("CA's Primary Certificate", certEntry);   //设置证书  
            X509CertificateEntry[] chain = new X509CertificateEntry[1];
            chain[0] = certEntry;
            store.SetKeyEntry("CA's Primary Certificate", new AsymmetricKeyEntry(priKey), chain);   //设置私钥  
            FileStream fout = File.Create("CA.pfx");
            
            store.Save(fout, passwd, new SecureRandom());   //保存  
            fout.Close();
        }
    }
}
