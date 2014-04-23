namespace FedMetaSignKeyThumbprintFinder
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Metadata;
    using System.IdentityModel.Tokens;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.ServiceModel.Security;
    using System.Xml;

    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("syntax: FedMetaSignKeyThumbprintFinder.exe federation-metadata-url");
                Environment.Exit(-1);
            }
            Console.WriteLine("Getting metadata...");
            Console.WriteLine();

            var certificates = GetSigningCertificates(args.First());

            Console.WriteLine("Thumbprint(s) of valid signing keys:");
            Console.WriteLine();

            certificates.ForEach(x => 
                    Console.WriteLine(x.Thumbprint.ToUpperInvariant()) );
            
            Console.WriteLine();
            Console.WriteLine("Done.");
        }

        // taken from http://msdn.microsoft.com/library/azure/dn641920.aspx and modified.
        public static List<X509Certificate2> GetSigningCertificates(string metadataAddress)
        {
            if (metadataAddress == null)
            {
                throw new ArgumentNullException("metadataAddress");
            }

            var certificates = new List<X509Certificate2>();


            using (var metadataReader = XmlReader.Create(metadataAddress))
            {
                var serializer = new MetadataSerializer
                {
                    CertificateValidationMode = X509CertificateValidationMode.None
                };

                var metadata = serializer.ReadMetadata(metadataReader) as EntityDescriptor;

                if (metadata != null)
                {
                    var stsd = metadata.RoleDescriptors.OfType<SecurityTokenServiceDescriptor>().First();

                    if (stsd != null)
                    {
                        var x509DataClauses = stsd.Keys.Where(key => key.KeyInfo != null && (key.Use == KeyType.Signing || key.Use == KeyType.Unspecified)).
                                                             Select(key => key.KeyInfo.OfType<X509RawDataKeyIdentifierClause>().First());

                        certificates.AddRange(x509DataClauses.Select(token => new X509Certificate2(token.GetX509RawData())));
                    }
                    else
                    {
                        throw new InvalidOperationException("There is no RoleDescriptor of type SecurityTokenServiceType in the metadata");
                    }
                }
                else
                {
                    throw new Exception("Invalid Federation Metadata document");
                }
            }
            return certificates;
        }
    }
}
