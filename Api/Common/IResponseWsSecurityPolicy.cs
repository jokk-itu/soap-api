using System.Xml;

namespace Api.Common;

public interface IResponseWsSecurityPolicy
{
    SoapOperationResult Apply(XmlElement soapEnvelope);
}