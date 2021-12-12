using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        // Symmetric key used for encripting and decrypting 
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));   

        }
        public string CreateToken(AppUser user)
        {
            var claims = new List<Claim>
            {
                // Name identifier (fore everything) to store user.Username
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };

            // Just use strongest algo to sign token
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            // Define token properties
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };
            
            // Must create handler for each token
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // Create token
            var token = tokenHandler.CreateToken(tokenDescriptor);
        
            // Return token as string to client
            return tokenHandler.WriteToken(token);
        }
    }
}