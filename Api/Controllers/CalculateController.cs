using Api.Contracts;
using Microsoft.AspNetCore.Mvc;
using Api.Common;

namespace Api.Controllers;

[ApiController]
[Route("/api/[controller]")]
public class CalculateController : ControllerBase
{
    private readonly ISoapClient<CalculateAddRequest, CalculateAddResponse> _calculateAddSoapClient;

    public CalculateController(
        ISoapClient<CalculateAddRequest, CalculateAddResponse> calculateAddSoapClient)
    {
        _calculateAddSoapClient = calculateAddSoapClient;
    }

    [HttpGet("v1/add")]
    public async Task<IActionResult> AddSoap(int a, int b, CancellationToken cancellationToken)
    {
        var request = new CalculateAddRequest
        {
            A = a,
            B = b
        };

        var response = await _calculateAddSoapClient.Post(request, cancellationToken);

        return Ok(response.Result);
    }
}
