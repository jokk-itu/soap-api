using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Api.Common;

public class EncryptedKeyWsSecurityPolicy : IRequestWsSecurityPolicy, IResponseWsSecurityPolicy
{
    private readonly ISoapAttributeGenerator _soapAttributeGenerator;
    private readonly string _soapNamespace;
    private readonly X509Certificate2 _certificate;

    public EncryptedKeyWsSecurityPolicy(
        ISoapAttributeGenerator soapAttributeGenerator,
        string soapNamespace,
        X509Certificate2 certificate)
    {
        _soapAttributeGenerator = soapAttributeGenerator;
        _soapNamespace = soapNamespace;
        _certificate = certificate;
    }

    public void Apply(XmlElement soapHeader, ICollection<WSSecurityOperation> wsSecurityOperations)
    {
        var ownerDocument = soapHeader.OwnerDocument;
        var namespaceManager = new XmlNamespaceManager(ownerDocument.NameTable);
        namespaceManager.AddNamespace("wsse", SoapConstants.Wss1_0Namespace);
        namespaceManager.AddNamespace("soap", _soapNamespace);
        var security = (XmlElement?)soapHeader.SelectSingleNode("wsse:Security", namespaceManager);

        if (security is null)
        {
            var newSecurityElement = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Security", SoapConstants.Wss1_0Namespace);
            _soapAttributeGenerator.GenerateMustUnderstandAttribute(newSecurityElement, true);
            soapHeader.AppendChild(newSecurityElement);
            security = newSecurityElement;
        }

        var encryptionKey = Aes.Create();
        var encryptionKeyId = Guid.NewGuid().ToString();

        AppendEncryptedKey(security, wsSecurityOperations, encryptionKey, encryptionKeyId);

        foreach (var wsSecurityOperation in wsSecurityOperations.Where(x => x.EncryptElement))
        {
            var encryptedXml = new EncryptedXmlWithId();
            var encryptedElement = encryptedXml.EncryptData(wsSecurityOperation.Element, encryptionKey, false);

            // https://stackoverflow.com/a/38594741/13576115
            var keyInfo = new KeyInfo();
            var securityTokenReference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss1_0Namespace);

            // This is recommended instead of using ValueType attribute
            securityTokenReference.SetAttribute("TokenType", SoapConstants.Wss1_1Namespace, SoapConstants.EncryptedKeyTokenType);

            var reference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Reference", SoapConstants.Wss1_0Namespace);
            reference.SetAttribute("URI", $"#{encryptionKeyId}");
            securityTokenReference.AppendChild(reference);
            keyInfo.AddClause(new KeyInfoNode(securityTokenReference));

            var encryptedData = new EncryptedData
            {
                Type = EncryptedXml.XmlEncElementUrl,
                EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
                KeyInfo = keyInfo,
                CipherData = new CipherData(encryptedElement)
            };

            // replaces the plain XmlElement with the EncryptedData in the XmlDocument directly
            EncryptedXml.ReplaceElement(wsSecurityOperation.Element, encryptedData, false);

            wsSecurityOperation.Element.SetAttribute("Id", SoapConstants.WsuNamespace, wsSecurityOperation.WsuId);
        }
    }

    private void AppendEncryptedKey(XmlElement securityHeader, ICollection<WSSecurityOperation> wsSecurityOperations, Aes encryptionKey, string encryptionKeyId)
    {
        var ownerDocument = securityHeader.OwnerDocument;

        // create a reference pointing to the certificate that encrypts the key
        var encryptedKeyInfo = new KeyInfo();
        var securityTokenReference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "SecurityTokenReference", SoapConstants.Wss1_0Namespace);
        var reference = ownerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "KeyIdentifier", SoapConstants.Wss1_0Namespace);
        reference.SetAttribute("EncodingType", SoapConstants.Base64EncodingType);
        reference.SetAttribute("ValueType", SoapConstants.ThumbprintValueType);
        var referenceText = ownerDocument.CreateTextNode(Convert.ToBase64String(Encoding.UTF8.GetBytes(_certificate.Thumbprint)));
        reference.AppendChild(referenceText);
        securityTokenReference.AppendChild(reference);
        encryptedKeyInfo.AddClause(new KeyInfoNode(securityTokenReference));

        // encrypt the key used to encrypt the message
        var encryptedKey = new EncryptedKey
        {
            Id = encryptionKeyId,
            CipherData = new CipherData(EncryptedXml.EncryptKey(encryptionKey.Key, _certificate.GetRSAPrivateKey()!, false)),
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            KeyInfo = encryptedKeyInfo
        };

        foreach (var wsSecurityOperation in wsSecurityOperations.Where(x => x.EncryptElement))
        {
            encryptedKey.ReferenceList.Add($"#{wsSecurityOperation.WsuId}");
        }
        
        var importedEncryptedKey = ownerDocument.ImportNode(encryptedKey.GetXml(), true);
        securityHeader.AppendChild(importedEncryptedKey);
    }

    public SoapOperationResult Apply(XmlElement soapEnvelope)
    {
        throw new NotImplementedException();
    }
}
