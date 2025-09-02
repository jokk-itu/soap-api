using System.Xml;

namespace Api.Common;

public sealed class Soap11AttributeGenerator : ISoapAttributeGenerator
{
    public void GenerateMustUnderstandAttribute(XmlElement element, bool value)
    {
        element.SetAttribute("mustUnderstand", SoapConstants.SoapVersion1_1Namespace, value ? "1" : "0");
    }
}
