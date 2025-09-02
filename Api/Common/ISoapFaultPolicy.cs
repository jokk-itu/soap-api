using System.Xml;

namespace Api.Common;

public interface ISoapFaultPolicy
{
    void Apply(XmlElement soapEnvelope);
}