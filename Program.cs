using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

var rsaKey = RSA.Create(2048);

var filePath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar + @"config.json";
if (!File.Exists(filePath))
{
    throw new FileNotFoundException(filePath);
}
        
using var file = File.OpenText(filePath);
using var reader = new JsonTextReader(file);
var config = (JObject)JToken.ReadFrom(reader);

// Must match the server url exactly, for example: 0.0.0.0 or localhost, or www.exemple.com
var subject = config.GetValue("Subject")?.ToString() ??  throw new KeyNotFoundException("No field Subject");//"CN=0.0.0.0"
// Certificate password
var password = config.GetValue("Password")?.ToString() ??  throw new KeyNotFoundException("No field Password");//"password";
// Certificate lifetime in years
var lifeTimeYears = int.Parse(config.GetValue("LifeTimeYears")?.ToString() ??  throw new KeyNotFoundException("No field LifeTimeYears")); //5;
// Export Certificate file name
var certificateFileName = config.GetValue("CertificateFileName")?.ToString() ??  throw new KeyNotFoundException("No field CertificateFileName"); //"CertName.pfx";

// Create certificate request, structure like list
var certificateRequest = new CertificateRequest(
    subject,
    rsaKey,
    HashAlgorithmName.SHA256,
    RSASignaturePadding.Pkcs1
);
certificateRequest.CertificateExtensions.Add(
    new X509BasicConstraintsExtension(
        certificateAuthority: false,
        hasPathLengthConstraint: false,
        pathLengthConstraint: 0,
        critical: true
    )
);
certificateRequest.CertificateExtensions.Add(
    new X509KeyUsageExtension(
        keyUsages:
        X509KeyUsageFlags.DigitalSignature
        | X509KeyUsageFlags.KeyEncipherment,
        critical: false
    )
);
certificateRequest.CertificateExtensions.Add(
    new X509SubjectKeyIdentifierExtension(
        key: certificateRequest.PublicKey,
        critical: false
    )
);
// Certificate validity period
var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(lifeTimeYears));

// Generate certificate with private key
var exportableCertificate = new X509Certificate2(
    certificate.Export(X509ContentType.Cert),
    (string)null!,
    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
).CopyWithPrivateKey(rsaKey);

// Password for certificate protection
var passwordForCertificateProtection = new SecureString();
foreach (var @char in password)
{
    passwordForCertificateProtection.AppendChar(@char);
}

// Export certificate to a file.
File.WriteAllBytes(
    certificateFileName,
    exportableCertificate.Export(
        X509ContentType.Pfx,
        passwordForCertificateProtection
    )
);