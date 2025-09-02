namespace Api.Common;

public interface ISoapClient<in TRequest, TResponse>
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TResponse> Post(TRequest request, CancellationToken cancellationToken);
}
