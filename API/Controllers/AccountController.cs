using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly ITokenService _tokenService;
        private DataContext _context;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        // structure to contain info on user password
        private struct PassHashSalt {
            public string password;
            public byte[] hash;
            public byte[] salt;
            
            public PassHashSalt(string pwd){ password = pwd; hash = null; salt = null;}
            public PassHashSalt(string pwd, byte[] slt){ password = pwd; hash = null; salt = slt;}
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto){
            
            // check if username already exists
            if (await UserExists(registerDto.Username.ToLower())) return BadRequest("Username is taken.");

            // hash and salt password
            PassHashSalt phs = HashAndSalt(new PassHashSalt(registerDto.Password));

            // create uesr info with password hash and salt
            var user = new AppUser {
                UserName = registerDto.Username.ToLower(),  // store username in lowercase
                PasswordHash = phs.hash,
                PasswordSalt = phs.salt                     // key used for encoding the password hash
            };

            // write and save changes to db
            _context.Users.Add(user);                       // track changes (user) in context
            await _context.SaveChangesAsync();              // save changes (add user to table)

            //return user
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
            var user = await _context.Users.SingleOrDefaultAsync(user => user.UserName == loginDto.Username.ToLower());
            if (user == null) return Unauthorized("Invalid username.");

            PassHashSalt phs = UnhashWithSalt(new PassHashSalt(loginDto.Password, user.PasswordSalt));

            for(int i = 0; i < phs.hash.Length; i++){
                if(phs.hash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password.");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        // Unsalt the user password hash to determine login
        private PassHashSalt UnhashWithSalt(PassHashSalt phs){
            using var hmac = new HMACSHA256(phs.salt);
            phs.hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(phs.password));
            return phs;
        }

        // Hash and salt the user password
        private PassHashSalt HashAndSalt(PassHashSalt phs){
            using var hmac = new HMACSHA256();
            phs.hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(phs.password));
            phs.salt = hmac.Key;
            return phs;
        }

        /// Verify if username is already used by other user
        /// Enforces unique usernames
        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(user => user.UserName == username.ToLower());
        }
    }
}