using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Api.Common;

public class BinaryTokenSigningWsSecurityPolicy : IRequestWsSecurityPolicy, IResponseWsSecurityPolicy
{
    private readonly X509Certificate2 _clientCertificate;
    private readonly X509Certificate2 _serviceCertificate;

    public BinaryTokenSigningWsSecurityPolicy(
        X509Certificate2 clientCertificate,
        X509Certificate2 serviceCertificate)
    {
        _clientCertificate = clientCertificate;
        _serviceCertificate = serviceCertificate;
    }

    public void Apply(XmlElement soapHeader, ICollection<WSSecurityOperation> wsSecurityOperations)
    {
        var ownerDocument = soapHeader.OwnerDocument;
        var namespaceManager = new XmlNamespaceManager(ownerDocument.NameTable);
        namespaceManager.AddNamespace("wsse", SoapConstants.Wss1_0Namespace);
        var security = (XmlElement)soapHeader.SelectSingleNode("wsse:Security", namespaceManager)!;

        var binarySecurityTokenId = $"uuid-{Guid.NewGuid()}-1";
        var binarySecurityToken = soapHeader.OwnerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "BinarySecurityToken", SoapConstants.Wss1_0Namespace);
        var binarySecurityTokenIdNode = soapHeader.OwnerDocument.CreateAttribute(SoapConstants.WsuPrefix, "Id", SoapConstants.WsuNamespace);
        binarySecurityTokenIdNode.Value = binarySecurityTokenId;
        binarySecurityToken.SetAttributeNode(binarySecurityTokenIdNode);
        binarySecurityToken.SetAttribute("ValueType", SoapConstants.CertificateValueType);
        // https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0.pdf
        binarySecurityToken.SetAttribute("EncodingType", SoapConstants.Base64EncodingType);
        security.AppendChild(binarySecurityToken);
        
        wsSecurityOperations.Add(new WSSecurityOperation
        {
            WsuId = binarySecurityTokenId,
            Element = binarySecurityToken,
            SignElement = true,
            EncryptElement = true
        });
        
        var binarySecurityTokenText = ownerDocument.CreateTextNode(Convert.ToBase64String(_clientCertificate.GetRawCertData()));
        binarySecurityToken.AppendChild(binarySecurityTokenText);

        var signedXml = new SignedXmlWithId(ownerDocument)
        {
            SigningKey = _clientCertificate.GetRSAPrivateKey()
        };

        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

        var transform = new XmlDsigExcC14NTransform();
        foreach (var wsSecurityOperation in wsSecurityOperations.Where(x => x.SignElement).OrderBy(x => x.WsuId))
        {
            var signableReference = new Reference
            {
                Uri = $"#{wsSecurityOperation.WsuId}"
            };
            signableReference.AddTransform(transform);
            signableReference.DigestMethod = SignedXml.XmlDsigSHA1Url;
            signedXml.AddReference(signableReference);
        }

        // https://stackoverflow.com/a/38594741/13576115
        var securityTokenReference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss1_0Namespace);

        var reference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Reference", SoapConstants.Wss1_0Namespace);
        reference.SetAttribute("ValueType", SoapConstants.CertificateValueType);
        reference.SetAttribute("URI", $"#{binarySecurityTokenId}");
        securityTokenReference.AppendChild(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoNode(securityTokenReference));

        signedXml.KeyInfo = keyInfo;

        signedXml.ComputeSignature();

        security.AppendChild(signedXml.GetXml());
    }

    public SoapOperationResult Apply(XmlElement soapEnvelope)
    {
        var namespaceManager = new XmlNamespaceManager(soapEnvelope.OwnerDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss1_0Namespace);
        namespaceManager.AddNamespace(SoapConstants.SigPrefix, SoapConstants.SigNamespace);

        var binarySecurityToken = soapEnvelope.SelectSingleNode("//wsse:Security/wsse:BinarySecurityToken", namespaceManager);
        if (binarySecurityToken is null)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        X509Certificate2 certificate;
        try
        {
            certificate = new X509Certificate2(Convert.FromBase64String(binarySecurityToken.InnerText));
        }
        catch (CryptographicException)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        if (_serviceCertificate.Thumbprint != certificate.Thumbprint)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        var signatures = soapEnvelope.SelectNodes("//wsse:Security/ds:Signature", namespaceManager)!;
        if (signatures.Count == 0)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        foreach (var signature in signatures)
        {
            if (signature is not XmlElement xmlSignature)
            {
                return new SoapOperationResult
                {
                    IsValid = false
                };
            }

            var signedXml = new SignedXmlWithId(soapEnvelope.OwnerDocument);
            signedXml.LoadXml(xmlSignature);

            var hasValidSignature = signedXml.CheckSignature(certificate, true);
            if (!hasValidSignature)
            {
                return new SoapOperationResult
                {
                    IsValid = false
                };
            }
        }

        return new SoapOperationResult
        {
            IsValid = true
        };
    }
}
