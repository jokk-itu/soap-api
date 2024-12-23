namespace Api;

public static class SoapFaultCodeConstants
{
    // https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383510
    // https://www.w3.org/TR/soap12-part1/#faultcodes
    public const string VersionMismatchFaultCode = "VersionMismatch";

    // https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383510
    // https://www.w3.org/TR/soap12-part1/#faultcodes
    public const string MustUnderstandFaultCode = "MustUnderstand";

    // https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383510
    public const string ClientFaultCode = "Client";

    // https://www.w3.org/TR/2000/NOTE-SOAP-20000508/#_Toc478383510
    public const string ServerFaultCode = "Server";

    // https://www.w3.org/TR/soap12-part1/#faultcodes
    public const string DataEncodingUnknown = "DataEncodingUnknown";

    // https://www.w3.org/TR/soap12-part1/#faultcodes
    public const string Sender = "Sender";

    // https://www.w3.org/TR/soap12-part1/#faultcodes
    public const string Receiver = "Receiver";
}