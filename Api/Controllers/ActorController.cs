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

        var responseEnvelope = await GetEnvelope(new ActorResponse
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

        var response = new ActorResponse
        {
            Id = Random.Shared.Next(0, 10000)
        };
        var signedEnvelope = await GetSignedEnvelope(response, "http://soap-api.com/actor");
        return Ok(signedEnvelope);
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

    private static async Task<XmlDocument> GetEnvelope<TBody>(TBody body, string bodyNamespace) where TBody : class
    {
        using var stream = new MemoryStream();
        var encoding = new UTF8Encoding(false);
        await using (var writer = new XmlTextWriter(stream, encoding))
        {
            writer.WriteStartDocument();

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Envelope", SoapConstants.SoapVersion1_1Namespace);
            writer.WriteAttributeString("xmlns", "req", null, bodyNamespace);

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

    private static async Task<XmlDocument> GetSignedEnvelope<TBody>(TBody body, string bodyNamespace) where TBody : class
    {
        var privateCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_private.p12");
        var publicCertificateBytes = await System.IO.File.ReadAllBytesAsync("oces3_public.cer");

        var privateCertificate = new X509Certificate2(privateCertificateBytes, "c5,PnmF8;m4I");
        var publicCertificate = new X509Certificate2(publicCertificateBytes);

        var binarySecurityTokenId = Guid.NewGuid();
        var bodyId = Guid.NewGuid().ToString();

        using var stream = new MemoryStream();
        var encoding = new UTF8Encoding(false);
        await using (var writer = new XmlTextWriter(stream, encoding))
        {
            writer.WriteStartDocument();

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Envelope", SoapConstants.SoapVersion1_1Namespace);
            writer.WriteAttributeString("xmlns", SoapConstants.Wss1_0Prefix, null, SoapConstants.Wss10Namespace);
            writer.WriteAttributeString("xmlns", SoapConstants.WsuPrefix, null, SoapConstants.WsuNamespace);
            writer.WriteAttributeString("xmlns", "req", null, bodyNamespace);

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Header", null);

            writer.WriteStartElement(SoapConstants.Wss1_0Prefix, "Security", null);
            writer.WriteAttributeString(SoapConstants.SoapPrefix, "mustUnderstand", null, "1");

            writer.WriteStartElement(SoapConstants.Wss1_0Prefix, "BinarySecurityToken", null);
            writer.WriteAttributeString(SoapConstants.WsuPrefix, "Id", null, binarySecurityTokenId.ToString());

            // https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0.pdf
            writer.WriteAttributeString("ValueType", SoapConstants.CertificateValueType);
            writer.WriteAttributeString("EncodingType", SoapConstants.Base64EncodingType);
            var rawCertificate = publicCertificate.GetRawCertData();
            writer.WriteBase64(rawCertificate, 0, rawCertificate.Length);

            // End BinarySecurityToken
            writer.WriteEndElement();

            // End Security
            writer.WriteEndElement();

            // End Header
            writer.WriteEndElement();

            writer.WriteStartElement(SoapConstants.SoapPrefix, "Body", null);
            writer.WriteAttributeString(SoapConstants.WsuPrefix, "Id", null, bodyId);

            var requestSerializer = new XmlSerializer(typeof(TBody), defaultNamespace: bodyNamespace);
            requestSerializer.Serialize(writer, body);

            // End Body
            writer.WriteEndElement();

            // End Envelope
            writer.WriteEndElement();
            writer.Flush();
        }

        // Convert stream to XmlDocument for signing
        var signableXml = Encoding.UTF8.GetString(stream.ToArray());
        var signableXmlDocument = new XmlDocument();
        signableXmlDocument.LoadXml(signableXml);

        // Sign the XML https://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html (SecurityTokenReference is being used)
        var signedXml = new SignedXmlWithId(signableXmlDocument)
        {
            SigningKey = privateCertificate.GetRSAPrivateKey()
        };

        var bodyReference = new Reference
        {
            Uri = $"#{bodyId}"
        };
        bodyReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(bodyReference);

        var keyInfo = new KeyInfo();
        var securityTokenReference = signableXmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss10Namespace);
        var binaryTokenReference = signableXmlDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Reference", SoapConstants.Wss10Namespace);
        binaryTokenReference.SetAttribute("URI", $"#{binarySecurityTokenId.ToString()}");
        binaryTokenReference.SetAttribute("ValueType", SoapConstants.CertificateValueType);
        securityTokenReference.AppendChild(binaryTokenReference);
        keyInfo.AddClause(new KeyInfoNode(securityTokenReference));
        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();

        var namespaceManager = new XmlNamespaceManager(signableXmlDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.SoapPrefix, SoapConstants.SoapVersion1_1Namespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss10Namespace);
        var security = signableXmlDocument.SelectSingleNode("soap:Envelope/soap:Header/wsse:Security", namespaceManager)!;
        security.AppendChild(signedXml.GetXml());

        return signableXmlDocument;
    }
}