using System.Xml;
using System.Xml.Serialization;

namespace Api.Common;

public sealed class Soap11FaultPolicy : ISoapFaultPolicy
{
    public void Apply(XmlElement soapEnvelope)
    {
        var namespaceManager = new XmlNamespaceManager(soapEnvelope.OwnerDocument.NameTable);
        namespaceManager.AddNamespace(SoapConstants.SoapPrefix, SoapConstants.SoapVersion1_1Namespace);

        var fault = soapEnvelope.SelectSingleNode("soap:Body/soap:Fault", namespaceManager);
        if (fault is not null)
        {
            var xmlSerializer = new XmlSerializer(typeof(Soap11Fault));
            using var stringReader = new StringReader(fault.InnerXml);
            var soap11Fault = (Soap11Fault?)xmlSerializer.Deserialize(stringReader);

            if (soap11Fault is null)
            {
                throw new UnknownSoapFaultException(fault);
            }

            throw new Soap11Exception(soap11Fault);
        }
    }
}