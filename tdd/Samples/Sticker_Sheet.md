## Links
Abstimmung: https://sli.do/tdd
Feedback: https://forms.office.com/r/44QHAn7H4W
Meetup Gruppe: https://www.meetup.com/Software-Technology-Meetup-Pforzheim
Kontakt: https://linktr.ee/ginomessmer
GitHub Repository: https://github.com/ginomessmer/voxium
Slides: https://github.com/ginomessmer/slides

## Hash Service
```cs
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Voxium.Shared.Data;

namespace Voxium.Shared.Services
{
    public class HMACSHA512HashService : IHashService
    {
        #region Implementation of IHashService

        /// <inheritdoc />
        public SignedHashValue Create(string input)
        {
            using var hmac = new HMACSHA512();
            var hash = hmac.ComputeHash(Encode(input));
            return new SignedHashValue(hash, hmac.Key);
        }

        /// <inheritdoc />
        public bool Verify(string input, SignedHashValue hash)
        {
            using var hmac = new HMACSHA512(hash.Salt);
            var computeHash = hmac.ComputeHash(Encode(input));

            var result = computeHash.SequenceEqual(hash.Hash);
            return result;
        }

        #endregion

        private static byte[] Encode(string input) => Encoding.UTF8.GetBytes(input);
    }
}
```

## Test
```cs
using System;
using System.ComponentModel;
using System.Text;
using Voxium.Shared.Data;
using Voxium.Shared.Services;
using Xunit;

namespace Voxium.Tests.Core
{
    public class Hmacsha512HashSecurityTests
    {
        [Fact]
        public void Hash_Create_Successfully()
        {
            // Arrange
            var hashService = new HMACSHA512HashService();
            const string input = "Martha";

            // Act
            var (hash, salt) = hashService.Create(input);

            // Assert
            Assert.NotEmpty(hash);
            Assert.NotEmpty(salt);
        }

        [Theory]
        [InlineData("UPnZPzezpVaATjgfMh6FiruEfjuQ91yiLeU3q52lDWtb1jua53tXeat5dHLGNYIWaIFodP4oEb6e/Ry4W0XoFg==",
            "RiOWktyk+85o/9BxDrb2kaGaA3ln0EQ7jLLW9ETEYGQWvVl3vNQj8VHDYyT9gXf1eKju8UmLRCw+2JLY/8FMdqP5tC9n4bPghNzZ/IBukUiG5VCoqlR7cYHRYeVDy66SMiWyxXjzc3N/iSG6IjRtPhWlABaPj4ho+JPPq8pf1zc=",
            "Martha")]
        public void Hash_Verify_Correctly(string hash, string key, string input)
        {
            // Arrange
            var hashService = new HMACSHA512HashService();

            // Act
            var result = hashService.Verify(input,
                new SignedHashValue(Encode(hash), Encode(key)));

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Hash_CreateAndVerify_Correctly()
        {
            // Arrange
            var hashService = new HMACSHA512HashService();
            const string input = "Martha";

            // Act
            var hash = hashService.Create(input);

            var decodedOutput = new
            {
                Hash = Decode(hash.Hash),
                Salt = Decode(hash.Salt)
            };

            var result = hashService.Verify(input, hash);

            // Assert
            Assert.NotEmpty(decodedOutput.Hash);
            Assert.NotEmpty(decodedOutput.Salt);
            Assert.True(result);
        }

        private static string Decode(byte[] input) => Convert.ToBase64String(input);
        private static byte[] Encode(string input) => Convert.FromBase64String(input);
    }
}
```