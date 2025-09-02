using System.Xml;

namespace Api.Common;

public interface IRequestWsSecurityPolicy
{
    void Apply(XmlElement soapHeader, ICollection<WSSecurityOperation> wsSecurityOperations);
}