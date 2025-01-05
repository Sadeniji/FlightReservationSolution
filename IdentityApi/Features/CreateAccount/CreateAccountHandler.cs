using System.Security.Claims;
using FluentValidation;
using Grpc.Core;
using IdentityApi.Domain;
using IdentityApi.Infrastructure.Repository;
using Mapster;
using MapsterMapper;
using MediatR;
using Shared.Authentication;

namespace IdentityApi.Features.CreateAccount
{
    public class Request
    {
        public string? FullName { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? ConfirmPassword { get; set; }
    }

    public class Validation : AbstractValidator<Request>
    {
        public Validation()
        {
            RuleFor(m => m.Email).NotEmpty().EmailAddress();
            RuleFor(m => m.Password).NotEmpty()
            .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
            .WithMessage("Password must be at least one uppercase letter, one lowercase letter, and one special character");
            RuleFor(m => m.ConfirmPassword).NotEmpty().Equal(m => m.Password)
            .WithMessage("Confirm password must be the same as password");
        }
    }

    // create mapping configuration
    internal static class CreateAccountMapperConfiguration
    {
        public static void Register(TypeAdapterConfig config)
        {
            config.NewConfig<Request, AppUser>()
                .Map(d => d.PasswordHash, s => s.Password)
                .Map(d => d.UserName, s => s.Email);
        }
    }

    public record Command(Request Account) : IRequest<bool>;

    internal class Handler(IUnitOfWork unitOfWork, IValidator<Request> validator, IMapper mapper) : IRequestHandler<Command, bool>
    {
        public async Task<bool> Handle(Command request, CancellationToken cancellationToken)
        {
            var validationResult = await validator.ValidateAsync(request.Account, cancellationToken);

            if (!validationResult.IsValid)
            {
                var errors = validationResult.Errors.Select(e => e.ErrorMessage).ToList();
                throw new RpcException(new Status(StatusCode.InvalidArgument, string.Join("; ", errors)));
            }

            var mapData = mapper.From(request.Account).AdaptToType<AppUser>();
            await unitOfWork.AppUser.CreateAsync(mapData);
            var _user = await unitOfWork.AppUser.GetByEmail(mapData.Email!);
            List<Claim> claims = [
                new(ClaimTypes.Role, Roles.User),
                new(ClaimTypes.Email, _user!.Email!),
                new(ClaimTypes.Name, _user!.FullName!),
                new(PolicyNames.Key, PolicyNames.UserPolicy),
                new(Permissions.CanRead, false.ToString()),
                new(Permissions.CanUpdate, false.ToString()),
                new(Permissions.CanDelete, false.ToString()),
                new(Permissions.CanCreate, false.ToString())
            ];
            await unitOfWork.Claim.AssignClaims(_user, claims);
            return true;
        }
    }
}