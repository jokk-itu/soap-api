using System.Xml;

namespace Api.Common;

public interface ISoapAttributeGenerator
{
    void GenerateMustUnderstandAttribute(XmlElement element, bool value);
}
