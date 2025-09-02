using System.Xml;

namespace Api.Common;

public class TimestampWsSecurityPolicy : IRequestWsSecurityPolicy, IResponseWsSecurityPolicy
{
    private readonly ISoapAttributeGenerator _soapAttributeGenerator;
    private readonly int _expirationSeconds;
    private readonly bool _signTimestamp;
    private readonly bool _encryptTimestamp;

    public TimestampWsSecurityPolicy(
        ISoapAttributeGenerator soapAttributeGenerator,
        int expirationSeconds,
        bool signTimestamp,
        bool encryptTimestamp)
    {
        _soapAttributeGenerator = soapAttributeGenerator;
        _expirationSeconds = expirationSeconds;
        _signTimestamp = signTimestamp;
        _encryptTimestamp = encryptTimestamp;
    }

    public TimestampWsSecurityPolicy(ISoapAttributeGenerator soapAttributeGenerator)
        : this(soapAttributeGenerator, 60, true, true)
    {}

    public void Apply(XmlElement soapHeader, ICollection<WSSecurityOperation> wsSecurityOperations)
    {
        var namespaceManager = new XmlNamespaceManager(soapHeader.OwnerDocument.NameTable);
        namespaceManager.AddNamespace("wsse", SoapConstants.Wss1_0Namespace);
        var security = (XmlElement?)soapHeader.SelectSingleNode("wsse:Security", namespaceManager);

        if (security is null)
        {
            var newSecurityElement = soapHeader.OwnerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Security", SoapConstants.Wss1_0Namespace);
            _soapAttributeGenerator.GenerateMustUnderstandAttribute(newSecurityElement, true);
            soapHeader.AppendChild(newSecurityElement);
            security = newSecurityElement;
        }

        var timestampId = Guid.NewGuid().ToString();
        var timestamp = soapHeader.OwnerDocument.CreateElement(SoapConstants.WsuPrefix, "Timestamp", SoapConstants.WsuNamespace);
        timestamp.SetAttribute("Id", SoapConstants.WsuNamespace, timestampId);
        security.AppendChild(timestamp);

        var created = soapHeader.OwnerDocument.CreateElement(SoapConstants.WsuPrefix, "Created", SoapConstants.WsuNamespace);
        var createdText = soapHeader.OwnerDocument.CreateTextNode(DateTime.UtcNow.ToString("O"));
        created.AppendChild(createdText);
        timestamp.AppendChild(created);

        var expires = soapHeader.OwnerDocument.CreateElement(SoapConstants.WsuPrefix, "Expires", SoapConstants.WsuNamespace);
        var expiresText = soapHeader.OwnerDocument.CreateTextNode(DateTime.UtcNow.AddSeconds(_expirationSeconds).ToString("O"));
        expires.AppendChild(expiresText);
        timestamp.AppendChild(expires);

        wsSecurityOperations.Add(new WSSecurityOperation
        {
            WsuId = timestampId,
            Element = timestamp,
            SignElement = _signTimestamp,
            EncryptElement = _encryptTimestamp
        });
    }

    public SoapOperationResult Apply(XmlElement soapEnvelope)
    {
        var namespaceManager = new XmlNamespaceManager(soapEnvelope.OwnerDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.WsuPrefix, SoapConstants.WsuNamespace);
        namespaceManager.AddNamespace(SoapConstants.Wss1_0Prefix, SoapConstants.Wss1_0Namespace);
        var timestampElement = soapEnvelope.SelectSingleNode("//wsse:Security/wsu:Timestamp", namespaceManager);

        if (timestampElement is null)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        var createdElement = timestampElement.SelectSingleNode("wsu:Created", namespaceManager);
        if (createdElement is null)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        var expiresElement = timestampElement.SelectSingleNode("wsu:Expires", namespaceManager);
        if (expiresElement is null)
        {
            return new SoapOperationResult
            {
                IsValid = false
            };
        }

        var created = DateTime.Parse(createdElement.InnerXml).ToUniversalTime();
        var expires = DateTime.Parse(expiresElement.InnerXml).ToUniversalTime();
        var now = DateTime.UtcNow;

        return new SoapOperationResult
        {
            IsValid = created < now && expires > now
        };
    }
}
