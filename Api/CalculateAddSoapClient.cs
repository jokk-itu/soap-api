using Api.Common;
using Api.Contracts;

namespace Api;

public class CalculateAddSoapClient : Soap11Client<CalculateAddRequest, CalculateAddResponse>
{
    public CalculateAddSoapClient(
        IHttpClientFactory httpClientFactory,
        IEnumerable<IRequestWsSecurityPolicy> requestWsSecurityPolicies,
        IEnumerable<IResponseWsSecurityPolicy> responseWsSecurityPolicies)
        : base(httpClientFactory.CreateClient("SoapApi"), requestWsSecurityPolicies, responseWsSecurityPolicies, new Soap11FaultPolicy())
    {
    }

    protected override string RequestNamespace => "http://tempuri.org/";
    protected override string EndpointPath => "mockCalculatorSoap11";
    protected override string SoapActionUri => "http://tempuri.org/Add";
}