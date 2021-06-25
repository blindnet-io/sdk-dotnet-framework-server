using Blindnet.Utils;
using Blindnet.Exceptions;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Signers;
using System.Text;

namespace Blindnet
{
    /// <summary>
    /// Blindnet
    /// </summary>
    public class Blindnet
    {
        private static readonly DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly string _appID;
        private readonly Ed25519PrivateKeyParameters _appKey;
        private readonly string _appKeyString;
        private string _clientToken;
        private readonly string _apiEndpoint;

        private Blindnet(string appKey, string appId, string apiEndpoint)
        {
            this._appID = appId;
            this._appKeyString = appKey;
            var privateKeyBytes = Base64UrlEncoder.DecodeBytes(appKey);
            Stream privateStream = new MemoryStream(privateKeyBytes);
            this._appKey = new Ed25519PrivateKeyParameters(privateStream);
            this._apiEndpoint = apiEndpoint;
            this.RefreshClientToken();
        }

        /// <summary>
        /// Creates an instance of Blindnet.
        /// </summary>
        /// <param name="appId">Application ID</param>
        /// <param name="appKey">Application private Ed25519 key (base64 encoded)</param>
        /// <param name="apiEndpoint">Optional API endpoint URL. Default value is 'https://api.blindnet.io'</param>
        public static Blindnet Init(string appKey, string appId, string apiEndpoint = "https://api.blindnet.io")
        {
            return new Blindnet(appKey, appId, apiEndpoint);
        }

        /// <summary>
        /// Creates a JWT for non-registered users of your application, usually data senders.
        /// </summary>
        /// <param name="groupId">ID of the group to which a data sender is sending the data</param>
        /// <returns>JWT for a non-registered user</returns>
        public string CreateTempUserToken(string groupId)
        {
            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            if (!string.IsNullOrEmpty(groupId))
            {
                claims.Add(new Claim(AppSettings.TokenUserGroupIDParamName, groupId));
            }

            string tokenId = Guid.NewGuid().ToString();
            claims.Add(new Claim(AppSettings.TokenIDParamName, tokenId));

            return CreateAndSign(AppSettings.TempTokenName, claims, DateTime.Now.ToUniversalTime().AddMinutes(30));
        }

        /// <summary>
        /// Creates a JWT for registered users of your application, usually data receivers.
        /// </summary>
        /// <param name="userId">ID of a registered user</param>
        /// <param name="groupId">ID of the group to which a registered user belongs</param>
        /// <returns>JWT for a registered user</returns>
        public string CreateUserToken(string userId, string groupId)
        {
            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            if (!string.IsNullOrEmpty(userId))
            {
                claims.Add(new Claim(AppSettings.TokenUserIDParamName, userId));
            }

            if (!string.IsNullOrEmpty(groupId))
            {
                claims.Add(new Claim(AppSettings.TokenUserGroupIDParamName, groupId));
            }

            return CreateAndSign(AppSettings.RegularTokenName, claims, DateTime.Now.ToUniversalTime().AddHours(12));
        }
        
        private void RefreshClientToken()
        {
            var claims = new List<Claim>
            {
                new Claim(AppSettings.TokenAppIDParamName, _appID)
            };

            string tokenId = Guid.NewGuid().ToString();
            claims.Add(new Claim(AppSettings.TokenIDParamName, tokenId));

            this._clientToken = CreateAndSign(AppSettings.ClientTokenName, claims, DateTime.Now.ToUniversalTime().AddDays(1));
        }

        private string CreateAndSign(string tokenType, List<Claim> claims, DateTime expires)
        {
            var now = DateTime.Now.ToUniversalTime();

            var header = new JwtHeader
            {
                alg = "EdDSA",
                typ = tokenType
            };
            var headerString = JsonConvert.SerializeObject(header);
            var base64Header = Base64UrlEncoder.Encode(headerString);

            var notBefore = (int)Math.Round((now - epoch).TotalSeconds, 0);

            var paylod = new JwtPayload
            {
                nbf = notBefore,
                iat = notBefore,
                exp = (int)Math.Round((expires - epoch).TotalSeconds, 0)
            };

            foreach (var claim in claims)
            {
                switch (claim.Type)
                {
                    case AppSettings.TokenAppIDParamName:
                        paylod.app = claim.Value;
                        break;
                    case AppSettings.TokenIDParamName:
                        paylod.tid = claim.Value;
                        break;
                    case AppSettings.TokenUserIDParamName:
                        paylod.uid = claim.Value;
                        break;
                    case AppSettings.TokenUserGroupIDParamName:
                        paylod.gid = claim.Value;
                        break;
                    case AppSettings.TokenUserIDsListParamName:
                        paylod.uids = claim.Value;
                        break;
                    default:
                        break;
                }
            }

            var payloadString = JsonConvert.SerializeObject(paylod);
            var base64Payload = Base64UrlEncoder.Encode(payloadString);

            var stringToSign = $"{base64Header}.{base64Payload}";
            var signigInputBytes = Encoding.UTF8.GetBytes(stringToSign);

            var signer = new Ed25519Signer();
            signer.Init(true, _appKey);
            signer.BlockUpdate(signigInputBytes, 0, signigInputBytes.Length);

            var signatureBytes = signer.GenerateSignature();
            var signature = Base64UrlEncoder.Encode(signatureBytes);


            return $"{stringToSign}.{signature}";
        }


        /// <summary>
        /// Deletes an encrypted data key from blindnet.
        /// </summary>
        /// <param name="dataId">ID of the data to delete</param>
        /// <returns>True if the deletion is successful</returns>
        /// <exception cref="AuthenticationException">Thrown when authentication to blindnet fails.</exception>
        /// /// <exception cref="AuthenticationException">Thrown when request to blindnet is not successful.</exception>
        public async Task<bool> ForgetData(string dataId)
        {
            var msg = new HttpRequestMessage()
            {
                Method = HttpMethod.Delete,
                RequestUri = new Uri($"{this._apiEndpoint}/api/v1/documents/{dataId}")
            };

            return await this.MakeReq(msg, true, "Error while forgeting the data with id " + dataId);
        }

        /// <summary>
        /// Deletes all encrypted data keys of a given user.
        /// </summary>
        /// <param name="userId">ID of a user to revoke access</param>
        /// <returns>True if the access revocation is successful</returns>
        /// /// <exception cref="AuthenticationException">Thrown when authentication to blindnet fails.</exception>
        /// /// <exception cref="AuthenticationException">Thrown when request to blindnet is not successful.</exception>
        public async Task<bool> RevokeAccess(string userId)
        {
            var msg = new HttpRequestMessage()
            {
                Method = HttpMethod.Delete,
                RequestUri = new Uri($"{this._apiEndpoint}/api/v1/documents/user/{userId}")
            };

            return await this.MakeReq(msg, true, "Error while revoking access to user with id " + userId);
        }

        /// <summary>
        /// Deletes a user from blindnet.
        /// </summary>
        /// <param name="userId">ID of a user to delete</param>
        /// <returns>True if the deletion is successful</returns>
        /// /// <exception cref="AuthenticationException">Thrown when authentication to blindnet fails.</exception>
        /// /// <exception cref="AuthenticationException">Thrown when request to blindnet is not successful.</exception>
        public async Task<bool> ForgetUser(string userId)
        {
            var msg = new HttpRequestMessage()
            {
                Method = HttpMethod.Delete,
                RequestUri = new Uri($"{this._apiEndpoint}/api/v1/users/{userId}")
            };

            return await this.MakeReq(msg, true, "Error while forgeting the user with id " + userId);
        }

        /// <summary>
        /// Deletes all users that belong to the group and all their encrypted data keys.
        /// </summary>
        /// <param name="groupId">ID of a group to delete</param>
        /// <returns>True if the deletion is successful</returns>
        /// /// <exception cref="AuthenticationException">Thrown when authentication to blindnet fails.</exception>
        /// /// <exception cref="AuthenticationException">Thrown when request to blindnet is not successful.</exception>
        public async Task<bool> ForgetGroup(string groupId)
        {
            var msg = new HttpRequestMessage()
            {
                Method = HttpMethod.Delete,
                RequestUri = new Uri($"{this._apiEndpoint}/api/v1/group/{groupId}")
            };

            return await this.MakeReq(msg, true, "Error while forgeting the group with id " + groupId);
        }

        private async Task<bool> MakeReq(HttpRequestMessage msg, bool isFirst, string errMsg)
        {
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {this._clientToken}");

            var resultMessage = await client.SendAsync(msg);
            var httpCode = resultMessage.StatusCode;

            if (httpCode == HttpStatusCode.Unauthorized && isFirst)
            {
                this.RefreshClientToken();
                return await this.MakeReq(msg, false, errMsg);
            }
            else if (httpCode == HttpStatusCode.Unauthorized)
            {
                throw new AuthenticationException();
            }
            else if (httpCode == HttpStatusCode.OK)
            {
                return true;
            }
            else 
            {
                throw new BlindnetException(errMsg + ". API response was " + httpCode);
            }
        }
    }

    public class JwtHeader
    {
        public string alg { get; set; }
        public string typ { get; set; }
    }

    public class JwtPayload
    {
        public string app { get; set; }
        public string uid { get; set; }
        public string uids { get; set; }
        public string gid { get; set; }
        public string tid { get; set; }
        public long nbf { get; set; }
        public long exp { get; set; }
        public long iat { get; set; }
    }

}
