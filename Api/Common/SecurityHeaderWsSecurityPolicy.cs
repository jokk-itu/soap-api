using System.Xml;

namespace Api.Common;

public class SecurityHeaderWsSecurityPolicy : IRequestWsSecurityPolicy
{
    private readonly ISoapAttributeGenerator _soapAttributeGenerator;

    public SecurityHeaderWsSecurityPolicy(ISoapAttributeGenerator soapAttributeGenerator)
    {
        _soapAttributeGenerator = soapAttributeGenerator;
    }

    public void Apply(XmlElement soapHeader, ICollection<WSSecurityOperation> wsSecurityOperations)
    {
        var securityElement = soapHeader.OwnerDocument.CreateElement(SoapConstants.Wss1_0Prefix, "Security", SoapConstants.Wss1_0Namespace);
        soapHeader.AppendChild(securityElement);
        _soapAttributeGenerator.GenerateMustUnderstandAttribute(securityElement, true);
    }
}