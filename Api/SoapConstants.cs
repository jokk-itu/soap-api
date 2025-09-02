namespace Api;

public static class SoapConstants
{
    public const string SoapPrefix = "soap";
    public const string SoapVersion1_1Namespace = "http://schemas.xmlsoap.org/soap/envelope/";
    public const string SoapVersion1_2Namespace = "http://www.w3.org/2003/05/soap-envelope";
    public const string SoapEncodingPrefix = "enc";
    public const string SoapEncodingStyle = "http://schemas.xmlsoap.org/soap/encoding/";

    public const string ActorAttribute = "actor";
    public const string MustUnderstandAttribute = "mustUnderstand";
    public const string RoleAttribute = "role";

    public const string ActionHeader = "SOAPAction";

    public const string SigPrefix = "ds";
    public const string EncPrefix = "xenc";
    public const string Wss1_0Prefix = "wsse";
    public const string Wss1_1Prefix = "wsse11";
    public const string WsuPrefix = "wsu";

    public const string SigNamespace = "http://www.w3.org/2000/09/xmldsig#";
    public const string EncNamespace = "http://www.w3.org/2001/04/xmlenc#";
    public const string Wss1_0Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    public const string Wss1_1Namespace = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    public const string WsuNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

    public const string CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
    public const string Base64EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    public const string CertificateValueType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    public const string EncryptedKeyTokenType = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey";
    public const string ThumbprintValueType = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1";
}
