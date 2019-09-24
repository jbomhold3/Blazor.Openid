namespace Blazor.OpenId.Models
{
    public enum RequestModes
    {
        Json = 0,
        Form_Post
    }

    public enum SessionStates
    {
        Undefined = 0,
        Active = 1,
        Inactive = 2,
        NoConfig = 3,
    }
}
