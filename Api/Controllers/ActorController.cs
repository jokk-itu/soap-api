using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class ActorController : ControllerBase
{
    private readonly ILogger<ActorController> _logger;

    public ActorController(ILogger<ActorController> logger)
    {
        _logger = logger;
    }

    [HttpPost("anonymous")]
    [Consumes(MimeTypeConstants.SoapXml)]
    [Produces(MimeTypeConstants.SoapXml)]
    public async Task<IActionResult> Anonymous()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var xmlBody = await bodyReader.ReadToEndAsync();

        _logger.LogInformation("Received request {@Request}", xmlBody);

        var responseEnvelope = await GetPlainEnvelope(new ActorResponse
        {
            Id = Random.Shared.Next(0, 10000)
        }, "http://soap-api.com/actor");
        return Ok(responseEnvelope);
    }

    // https://stackoverflow.com/a/50008378/13576115
    [HttpPost("sign")]
    [Consumes(MimeTypeConstants.SoapXml)]
    [Produces(MimeTypeConstants.SoapXml)]
    public async Task<IActionResult> Sign()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var xmlBody = await bodyReader.ReadToEndAsync();

        var xmlDocument = new XmlDocument
        {
            PreserveWhitespace = true
        };
        xmlDocument.LoadXml(xmlBody);

        var binarySecurityTokens = xmlDocument.GetElementsByTagName("wsse:BinarySecurityToken");
        var binarySecurityToken = binarySecurityTokens.Item(0)?.InnerText;
        if (binarySecurityToken is null)
        {
            return BadRequest("missing security token");
        }

        var certificate = new X509Certificate2(Convert.FromBase64String(binarySecurityToken));

        var signatures = xmlDocument.GetElementsByTagName("Signature", SoapConstants.SigNamespace);
        if (signatures.Item(0) is not XmlElement signature)
        {
            return BadRequest("missing signature");
        }

        var signedXml = new SignedXmlWithId(xmlDocument);
        signedXml.LoadXml(signature);

        var hasValidSignature = signedXml.CheckSignature(certificate, true);
        if (!hasValidSignature)
        {
            return BadRequest("signature is not valid");
        }

        if (!HasValidTimestamp(xmlDocument))
        {
            var messageExpiredFault = new Soap11Fault<string>
            {
                FaultCode = SoapFaultCodeConstants.ClientFaultCode,
                FaultString = "Message has expired"
            };
            var signedFaultEnvelope = await GetSignedEnvelope(messageExpiredFault);
            return BadRequest(signedFaultEnvelope);
        }

        var response = new ActorResponse
        {
            Id = Random.Shared.Next(0, 10000)
        };
        var signedEnvelope = await GetSignedEnvelope(response, "http://soap-api.com/actor");
        return Ok(signedEnvelope);
    }

    [HttpPost("encrypt")]
    [Consumes(MimeTypeConstants.SoapXml)]
    [Produces(MimeTypeConstants.SoapXml)]
    public async Task<IActionResult> Encrypt()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var xmlBody = await bodyReader.ReadToEndAsync();

        var xmlDocument = new XmlDocument
        {
            PreserveWhitespace = true
        };
        xmlDocument.LoadXml(xmlBody);

        var namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.SoapPrefix, SoapConstants.SoapVersion1_1Namespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss1_0Namespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_1Prefix, SoapConstants.Wss1_1Namespace);
        namespaceManager.AddNamespace(SoapConstants.WsuPrefix, SoapConstants.WsuNamespace);
        namespaceManager.AddNamespace(SoapConstants.EncPrefix, SoapConstants.EncNamespace);
        namespaceManager.AddNamespace(SoapConstants.SigPrefix, SoapConstants.SigNamespace);

        var privateCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_private.p12");
        var privateCertificate = new X509Certificate2(privateCertificateBytes, "c5,PnmF8;m4I");

        var encryptedKeyXml = (xmlDocument.SelectSingleNode("soap:Envelope/soap:Header/wsse:Security/xenc:EncryptedKey", namespaceManager) as XmlElement)!;
        var encryptedKey = new EncryptedKey();
        encryptedKey.LoadXml(encryptedKeyXml);

        var keyIdentifier = (encryptedKeyXml.SelectSingleNode("ds:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier", namespaceManager) as XmlElement)!;
        var decodedThumbprint = Encoding.UTF8.GetString(Convert.FromBase64String(keyIdentifier.InnerText));
        if (decodedThumbprint != privateCertificate.Thumbprint)
        {
            return BadRequest("EncryptedKey cannot be identified");
        }

        var symmetricKey = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue!, privateCertificate.GetRSAPrivateKey()!, false);
        var aes = Aes.Create();
        aes.Key = symmetricKey;

        var encryptedDataXml = (xmlDocument.SelectSingleNode("soap:Envelope/soap:Body/xenc:EncryptedData", namespaceManager) as XmlElement)!;
        var encryptedData = new EncryptedData();
        encryptedData.LoadXml(encryptedDataXml);

        var referenceUri = encryptedKey.ReferenceList.Item(0)?.Uri;
        var encryptedDataId = encryptedDataXml.GetAttribute("Id", SoapConstants.WsuNamespace);
        if (referenceUri != $"#{encryptedDataId}")
        {
            return BadRequest("EncryptedKey does not reference EncryptedData");
        }

        var encryptedXml = new EncryptedXmlWithId();
        var decryptedData = encryptedXml.DecryptData(encryptedData, aes);
        var decryptedDataXml = Encoding.UTF8.GetString(decryptedData);
        _logger.LogInformation("Received request {@Request}", decryptedDataXml);

        var response = new ActorResponse
        {
            Id = Random.Shared.Next(0, 10000)
        };
        var encryptedEnvelope = await GetEncryptedEnvelope(response, "http://soap-api.com/actor");
        return Ok(encryptedEnvelope);
    }

    [HttpGet("sign")]
    [Produces(MimeTypeConstants.SoapXml)]
    public async Task<IActionResult> GetSignedRequest()
    {
        var request = new ActorRequest
        {
            Name = "John Doe"
        };

        var signedEnvelope = await GetSignedEnvelope(request, "http://soap-api.com/actor");
        return Ok(signedEnvelope);
    }

    [HttpGet("encrypt")]
    [Produces(MimeTypeConstants.SoapXml)]
    public async Task<IActionResult> GetEncryptedRequest()
    {
        var request = new ActorRequest
        {
            Name = "John Doe"
        };

        var encryptedEnvelope = await GetEncryptedEnvelope(request, "http://soap-api.com/actor");
        return Ok(encryptedEnvelope);
    }

    private static async Task<XmlDocument> GetPlainEnvelope<TBody>(TBody body, string bodyNamespace) where TBody : class
    {
        using var stream = new MemoryStream();
        var encoding = new UTF8Encoding(false);
        await using (var writer = new XmlTextWriter(stream, encoding))
        {
            writer.WriteStartDocument();

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Envelope", SoapConstants.SoapVersion1_1Namespace);
            writer.WriteAttributeString("xmlns", "request", null, bodyNamespace);

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Body", null);

            var requestSerializer = new XmlSerializer(typeof(TBody), defaultNamespace: bodyNamespace);
            requestSerializer.Serialize(writer, body);

            // End Body
            writer.WriteEndElement();

            // End Envelope
            writer.WriteEndElement();
            writer.Flush();
        }

        var xml = Encoding.UTF8.GetString(stream.ToArray());
        var xmlDocument = new XmlDocument();
        xmlDocument.LoadXml(xml);
        return xmlDocument;
    }

    private static async Task<XmlDocument> GetEncryptedEnvelope<TMessage>(TMessage message, string? bodyNamespace = null)
        where TMessage : class
    {
        var encryptionKey = Aes.Create();

        var bodyId = Guid.NewGuid().ToString();
        var messageId = Guid.NewGuid().ToString();
        var encryptionKeyId = Guid.NewGuid().ToString();

        var privateCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_private.p12");
        var privateCertificate = new X509Certificate2(privateCertificateBytes, "c5,PnmF8;m4I");

        var xmlDocument = new XmlDocument();
        var envelope = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Envelope", SoapConstants.SoapVersion1_1Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_0Prefix}", SoapConstants.Wss1_0Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_1Prefix}", SoapConstants.Wss1_1Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.WsuPrefix}", SoapConstants.WsuNamespace);
        if (bodyNamespace is not null)
        {
            envelope.SetAttribute("xmlns:message", bodyNamespace);
        }
        xmlDocument.AppendChild(envelope);

        var header = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Header", SoapConstants.SoapVersion1_1Namespace);
        envelope.AppendChild(header);

        var security = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Security", SoapConstants.Wss1_0Namespace);
        security.SetAttribute("mustUnderstand", SoapConstants.SoapVersion1_1Namespace, "1");
        header.AppendChild(security);

        // create a reference pointing to the certificate that encrypts the key
        var encryptedKeyInfo = new KeyInfo();
        var securityTokenReference = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss1_0Namespace);
        var reference = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "KeyIdentifier", SoapConstants.Wss1_0Namespace);
        reference.SetAttribute("EncodingType", SoapConstants.Base64EncodingType);
        reference.SetAttribute("ValueType", SoapConstants.ThumbprintValueType);
        var referenceText = xmlDocument.CreateTextNode(Convert.ToBase64String(Encoding.UTF8.GetBytes(privateCertificate.Thumbprint)));
        reference.AppendChild(referenceText);
        securityTokenReference.AppendChild(reference);
        encryptedKeyInfo.AddClause(new KeyInfoNode(securityTokenReference));

        // encrypt the key used to encrypt the message
        var encryptedKey = new EncryptedKey
        {
            Id = encryptionKeyId,
            CipherData = new CipherData(EncryptedXml.EncryptKey(encryptionKey.Key, privateCertificate.GetRSAPrivateKey()!, false)),
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            ReferenceList = { new DataReference($"#{messageId}") },
            KeyInfo = encryptedKeyInfo
        };

        var importedEncryptedKey = xmlDocument.ImportNode(encryptedKey.GetXml(), true);
        security.AppendChild(importedEncryptedKey);

        var body = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Body", SoapConstants.SoapVersion1_1Namespace);
        body.SetAttribute("Id", SoapConstants.WsuNamespace, bodyId);

        // the body must be appended to the envelope before navigation can occur
        envelope.AppendChild(body);

        using (var xmlWriter = body.CreateNavigator()!.AppendChild())
        {
            // write an empty whitespace to force omit the XML declaration
            xmlWriter.WriteWhitespace("");

            var xmlSerializer = new XmlSerializer(typeof(TMessage));
            var namespaces = new[] { new XmlQualifiedName("request", bodyNamespace) };
            xmlSerializer.Serialize(xmlWriter, message, new XmlSerializerNamespaces(namespaces));
        }

        // insert a wsu:Id to the message element
        (body.FirstChild as XmlElement)!.SetAttribute("Id", SoapConstants.WsuNamespace, messageId);

        // Encrypt the request in the body
        var elementToEncrypt = (body.FirstChild as XmlElement)!;
        var encryptedXml = new EncryptedXmlWithId();
        var encryptedElement = encryptedXml.EncryptData(elementToEncrypt, encryptionKey, false);

        // Build the EncryptedData to replace the plain Xml element
        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            KeyInfo = GetReferenceKeyInfo(xmlDocument, $"#{encryptionKeyId}", SoapConstants.EncryptedKeyTokenType),
            CipherData = new CipherData(encryptedElement)
        };

        // replaces the plain XmlElement with the EncryptedData in the XmlDocument directly
        EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);

        // insert a wsu:Id to the EncryptedData element
        (body.FirstChild as XmlElement)!.SetAttribute("Id", SoapConstants.WsuNamespace, messageId);

        return xmlDocument;
    }

    private static async Task<XmlDocument> GetSignedEnvelope<TMessage>(TMessage message, string? bodyNamespace = null)
        where TMessage : class
    {
        var privateCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_private.p12");
        var publicCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_public.cer");

        var privateCertificate = new X509Certificate2(privateCertificateBytes, "c5,PnmF8;m4I");
        var publicCertificate = new X509Certificate2(publicCertificateBytes);

        var timestampId = Guid.NewGuid().ToString();
        var binarySecurityTokenId = Guid.NewGuid().ToString();
        var bodyId = Guid.NewGuid().ToString();

        var xmlDocument = new XmlDocument();
        var envelope = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Envelope", SoapConstants.SoapVersion1_1Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_0Prefix}", SoapConstants.Wss1_0Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.Wss1_1Prefix}", SoapConstants.Wss1_1Namespace);
        envelope.SetAttribute($"xmlns:{SoapConstants.WsuPrefix}", SoapConstants.WsuNamespace);
        if (bodyNamespace is not null)
        {
            envelope.SetAttribute("xmlns:message", bodyNamespace);
        }
        xmlDocument.AppendChild(envelope);

        var header = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Header", SoapConstants.SoapVersion1_1Namespace);
        envelope.AppendChild(header);

        var security = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Security", SoapConstants.Wss1_0Namespace);
        security.SetAttribute("mustUnderstand", SoapConstants.SoapVersion1_1Namespace, "1");
        header.AppendChild(security);

        var timestamp = xmlDocument.CreateElement(SoapConstants.WsuPrefix, "Timestamp", SoapConstants.WsuNamespace);
        timestamp.SetAttribute("Id", SoapConstants.WsuNamespace, timestampId);
        security.AppendChild(timestamp);

        var created = xmlDocument.CreateElement(SoapConstants.WsuPrefix, "Created", SoapConstants.WsuNamespace);
        var createdText = xmlDocument.CreateTextNode(DateTime.UtcNow.ToString("O"));
        created.AppendChild(createdText);
        timestamp.AppendChild(created);

        var expires = xmlDocument.CreateElement(SoapConstants.WsuPrefix, "Expires", SoapConstants.WsuNamespace);
        var expiresText = xmlDocument.CreateTextNode(DateTime.UtcNow.AddSeconds(60).ToString("O"));
        expires.AppendChild(expiresText);
        timestamp.AppendChild(expires);

        var binarySecurityToken = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "BinarySecurityToken", SoapConstants.Wss1_0Prefix);
        binarySecurityToken.SetAttribute("Id", SoapConstants.WsuNamespace, binarySecurityTokenId);
        // https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0.pdf
        binarySecurityToken.SetAttribute("EncodingType", SoapConstants.Base64EncodingType);
        binarySecurityToken.SetAttribute("ValueType", SoapConstants.CertificateValueType);
        var binarySecurityTokenText = xmlDocument.CreateTextNode(Convert.ToBase64String(publicCertificate.GetRawCertData()));
        binarySecurityToken.AppendChild(binarySecurityTokenText);
        security.AppendChild(binarySecurityToken);

        var body = xmlDocument.CreateElement(SoapConstants.SoapPrefix, "Body", SoapConstants.SoapVersion1_1Namespace);
        body.SetAttribute("Id", SoapConstants.WsuNamespace, bodyId);
       
        // the body must be appended to the envelope before navigation can occur
        envelope.AppendChild(body);
        
        using (var xmlWriter = body.CreateNavigator()!.AppendChild())
        {
            // write an empty whitespace to force omit the Xml declaration
            xmlWriter.WriteWhitespace("");

            var xmlSerializer = new XmlSerializer(typeof(TMessage));
            var namespaces = new[] {new XmlQualifiedName("request", bodyNamespace)};
            xmlSerializer.Serialize(xmlWriter, message, new XmlSerializerNamespaces(namespaces));
        }

        // Sign the XML https://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html (SecurityTokenReference is being used)
        var signedXml = new SignedXmlWithId(xmlDocument)
        {
            SigningKey = privateCertificate.GetRSAPrivateKey()
        };

        var timestampReference = new Reference
        {
            Uri = $"#{timestampId}"
        };
        timestampReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(timestampReference);

        var binarySecurityTokenReference = new Reference
        {
            Uri = $"#{binarySecurityTokenId}"
        };
        binarySecurityTokenReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(binarySecurityTokenReference);
   
        var bodyReference = new Reference
        {
            Uri = $"#{bodyId}"
        };
        bodyReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(bodyReference);

        signedXml.KeyInfo = GetReferenceKeyInfo(xmlDocument, $"#{binarySecurityTokenId}", SoapConstants.CertificateValueType);

        signedXml.ComputeSignature();

        security.AppendChild(signedXml.GetXml());

        return xmlDocument;
    }

    private static bool HasValidTimestamp(XmlDocument xmlDocument)
    {
        var namespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.SoapPrefix, SoapConstants.SoapVersion1_1Namespace);
        namespaceManager.AddNamespace(SoapConstants.WsuPrefix, SoapConstants.WsuNamespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss1_0Namespace);
        var timestampElement = xmlDocument.SelectSingleNode("soap:Envelope/soap:Header/wsse:Security/wsu:Timestamp", namespaceManager)!;

        var createdElement = timestampElement.SelectSingleNode("wsu:Created", namespaceManager)!.InnerText;
        var created = DateTime.Parse(createdElement).ToUniversalTime();

        var expiresElement = timestampElement.SelectSingleNode("wsu:Expires", namespaceManager)!.InnerText;
        var expires = DateTime.Parse(expiresElement).ToUniversalTime();
        var now = DateTime.UtcNow;
        return created < now && expires > now;
    }

    private static KeyInfo GetReferenceKeyInfo(XmlDocument xmlDocument, string uri, string tokenType)
    {
        // https://stackoverflow.com/a/38594741/13576115
        var keyInfo = new KeyInfo();
        var securityTokenReference = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss1_0Namespace);

        // This is recommended instead of using ValueType attribute
        securityTokenReference.SetAttribute("TokenType", SoapConstants.Wss1_1Namespace, tokenType);

        var reference = xmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Reference", SoapConstants.Wss1_0Namespace);
        reference.SetAttribute("URI", uri);
        securityTokenReference.AppendChild(reference);
        keyInfo.AddClause(new KeyInfoNode(securityTokenReference));

        return keyInfo;
    }
}