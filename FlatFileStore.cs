// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Utilities;

namespace Identity.FlatFileStore
{
    public class FlatFileStore<TUser, TRole> :
        IUserLoginStore<TUser>,
        IUserRoleStore<TUser>,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IQueryableRoleStore<TRole>,
        IRoleClaimStore<TRole>
        where TRole : FlatFileRole, new()
        where TUser : FlatFileUser, new()
    {
        public FlatFileStore(
            string path,
            TimeSpan cacheExpiration,
            int saveDebounceInMs = 500)
        {
            _userRootDirectory = path.EnsureFullPath();
            if (!Directory.Exists(_userRootDirectory))
                Directory.CreateDirectory(_userRootDirectory);

            _cacheExpiration = cacheExpiration;
            _saveDebounce = saveDebounceInMs;
            _dirtyUsers = new Timer(saveUsers, null, Timeout.Infinite, Timeout.Infinite);
            _dirtyRoles = new Timer(saveRoles, null, Timeout.Infinite, Timeout.Infinite);
        }

        private readonly IMemoryCache cache = new MemoryCache(new MemoryCacheOptions());
        private readonly string _userRootDirectory;
        private const string _userExt = ".jusr";
        private const string _roleExt = ".jrle";
        private readonly Timer _dirtyUsers;
        private readonly Timer _dirtyRoles;
        private readonly TimeSpan _cacheExpiration;
        private readonly int _saveDebounce;

        private readonly static object _userLock = new object();
        private Dictionary<string, TUser> _users
        {
            get
            {
                lock (_userLock)
                {
                    Dictionary<string, TUser> result = cache.Get<Dictionary<string, TUser>>("_users_");
                    if (result == null)
                    {
                        result = new Dictionary<string, TUser>();
                        foreach (string f in Directory.EnumerateFiles(_userRootDirectory, "*" + _userExt, SearchOption.TopDirectoryOnly))
                            result.Add(Path.GetFileNameWithoutExtension(f), new TUser().JsonReadFrom(f));
                        cache.Set<Dictionary<string, TUser>>("_users_", result,
                            new MemoryCacheEntryOptions().SetSlidingExpiration(_cacheExpiration));
                        Debug.WriteLine(String.Format("{0} user(s) restored", result.Count), "FlatFileStore");
                    }
                    return result;
                }
            }
        }
        private void deleteUser(TUser user)
        {
            File.Delete(Path.Combine(_userRootDirectory, user.Id + _userExt));
        }
        private void saveUsers(object state)
        {
            _dirtyUsers.Change(Timeout.Infinite, Timeout.Infinite);
            foreach (TUser u in _users.Values)
                if (u.Changed)
                {
                    u.JsonWriteTo(Path.Combine(_userRootDirectory, u.Id + _userExt));
                    u.Changed = false;
                    Debug.WriteLine(String.Format("user {0} saved", u.Id), "FlatFileStore");
                }
        }
        private void dirtyUser(TUser user)
        {
            user.Changed = true;
            _dirtyUsers.Change(_saveDebounce, Timeout.Infinite);
        }
        public IQueryable<TUser> Users
        {
            get { return _users.Values.AsQueryable(); }
        }

        // not used any more...
        //private readonly Dictionary<string, TUser> _logins = new Dictionary<string, TUser>();

        private readonly static object _roleLock = new object();
        private Dictionary<string, TRole> _roles
        {
            get
            {
                lock (_roleLock)
                {
                    Dictionary<string, TRole> result = cache.Get<Dictionary<string, TRole>>("_roles_");
                    if (result == null)
                    {
                        result = new Dictionary<string, TRole>();
                        foreach (string f in Directory.EnumerateFiles(_userRootDirectory, "*" + _roleExt, SearchOption.TopDirectoryOnly))
                            result.Add(Path.GetFileNameWithoutExtension(f), new TRole().JsonReadFrom(f));
                        cache.Set<Dictionary<string, TRole>>("_roles_", result,
                            new MemoryCacheEntryOptions().SetSlidingExpiration(_cacheExpiration));
                        Debug.WriteLine(String.Format("{0} role(s) restored", result.Count), "FlatFileStore");
                    }
                    return result;
                }
            }
        }
        private void deleteRole(TRole role)
        {
            File.Delete(Path.Combine(_userRootDirectory, role.Id + _roleExt));
        }
        private void saveRoles(object state)
        {
            _dirtyRoles.Change(Timeout.Infinite, Timeout.Infinite);
            foreach (TRole r in _roles.Values)
                if (r.Changed)
                {
                    r.JsonWriteTo(Path.Combine(_userRootDirectory, r.Id + _roleExt));
                    r.Changed = false;
                    Debug.WriteLine(String.Format("role {0} saved", r.Id), "FlatFileStore");
                }
        }
        private void dirtyRole(TRole role)
        {
            role.Changed = true;
            _dirtyRoles.Change(_saveDebounce, Timeout.Infinite);
        }
        public IQueryable<TRole> Roles
        {
            get { return _roles.Values.AsQueryable(); }
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            var claims = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult<IList<Claim>>(claims);
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            foreach (var claim in claims)
            {
                user.Claims.Add(new FlatFileUserClaim { ClaimType = claim.Type, ClaimValue = claim.Value, UserId = user.Id });
            }
            if (claims.Count() > 0)
                dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            var matchedClaims = user.Claims.Where(uc => uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToList();
            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }
            if (matchedClaims.Count > 0)
                dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            foreach (var claim in claims)
            {
                var entity =
                    user.Claims.FirstOrDefault(
                        uc => uc.UserId == user.Id && uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value);
                if (entity != null)
                {
                    user.Claims.Remove(entity);
                    dirtyUser(user);
                }
            }
            return Task.FromResult(0);
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.Email = email;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.Email);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.NormalizedEmail = normalizedEmail;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.EmailConfirmed = confirmed;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<TUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            return
                Task.FromResult(
                    Users.FirstOrDefault(u => u.NormalizedEmail == email));
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.LockoutEnd = lockoutEnd;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.AccessFailedCount++;
            dirtyUser(user);
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.AccessFailedCount = 0;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.LockoutEnabled = enabled;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        //private string GetLoginKey(string loginProvider, string providerKey)
        //{
        //    return loginProvider + "|" + providerKey;
        //}

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            // may be we should check if allready used...
            user.Logins.Add(new FlatFileUserLogin
            {
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName
            });
            dirtyUser(user);
            //_logins[GetLoginKey(login.LoginProvider, login.ProviderKey)] = user;
            return Task.FromResult(0);
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var loginEntity =
                user.Logins.SingleOrDefault(l => l.ProviderKey == providerKey && l.LoginProvider == loginProvider);
            if (loginEntity != null)
            {
                user.Logins.Remove(loginEntity);
                dirtyUser(user);
            }
            //_logins[GetLoginKey(loginProvider, providerKey)] = null;
            return Task.FromResult(0);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            IList<UserLoginInfo> result = user.Logins
                .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName)).ToList();
            return Task.FromResult(result);
        }

        public Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            //string key = GetLoginKey(loginProvider, providerKey);
            //if (_logins.ContainsKey(key))
            //{
            //    return Task.FromResult(_logins[key]);
            //}
            foreach (TUser p in _users.Values)
            {
                if (p.Logins.FirstOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey) != null)
                    return Task.FromResult(p);
            }

            return Task.FromResult<TUser>(null);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.UserName);
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.UserName = userName;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            _users[user.Id] = user;
            dirtyUser(user);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            _users[user.Id] = user;
            dirtyUser(user);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (_users.ContainsKey(userId))
            {
                return Task.FromResult(_users[userId]);
            }
            return Task.FromResult<TUser>(null);
        }

        public void Dispose()
        {
        }

        public Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            return
                Task.FromResult(
                    Users.FirstOrDefault(u => u.NormalizedUserName == userName));
        }

        public Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (user == null || !_users.ContainsKey(user.Id))
            {
                throw new InvalidOperationException("Unknown user");
            }
            _users.Remove(user.Id);
            deleteUser(user);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.PasswordHash = passwordHash;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.PhoneNumber = phoneNumber;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.PhoneNumberConfirmed = confirmed;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        // RoleId == roleName for InMemory
        public Task AddToRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            var roleEntity = _roles.Values.SingleOrDefault(r => r.NormalizedName == role);
            if (roleEntity != null)
            {
                user.Roles.Add(new FlatFileUserRole { RoleId = roleEntity.Id, UserId = user.Id });
                dirtyUser(user);
            }
            return Task.FromResult(0);
        }

        // RoleId == roleName for InMemory
        public Task RemoveFromRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            var roleObject = _roles.Values.SingleOrDefault(r => r.NormalizedName == role);
            var roleEntity = user.Roles.SingleOrDefault(ur => ur.RoleId == roleObject.Id);
            if (roleEntity != null)
            {
                user.Roles.Remove(roleEntity);
                dirtyUser(user);
            }
            return Task.FromResult(0);
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            IList<string> roles = new List<string>();
            foreach (var r in user.Roles.Select(ur => ur.RoleId))
            {
                roles.Add(_roles[r].Name);
            }
            return Task.FromResult(roles);
        }

        public Task<bool> IsInRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            var roleObject = _roles.Values.SingleOrDefault(r => r.NormalizedName == role);
            bool result = roleObject != null && user.Roles.Any(ur => ur.RoleId == roleObject.Id);
            return Task.FromResult(result);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.SecurityStamp = stamp;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.TwoFactorEnabled = enabled;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            user.NormalizedUserName = userName;
            dirtyUser(user);
            return Task.FromResult(0);
        }

        // RoleId == rolename for inmemory store tests
        public Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (String.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var role = _roles.Values.Where(x => x.NormalizedName.Equals(roleName)).SingleOrDefault();
            if (role == null)
            {
                return Task.FromResult<IList<TUser>>(new List<TUser>());
            }
            return Task.FromResult<IList<TUser>>(Users.Where(u => (u.Roles.Where(x => x.RoleId == role.Id).Count() > 0)).Select(x => x).ToList());
        }

        public Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            var query = from user in Users
                        where user.Claims.Where(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value).FirstOrDefault() != null
                        select user;

            return Task.FromResult<IList<TUser>>(query.ToList());
        }

        public Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            _roles[role.Id] = role;
            dirtyRole(role);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (role == null || !_roles.ContainsKey(role.Id))
            {
                throw new InvalidOperationException("Unknown role");
            }
            _roles.Remove(role.Id);
            deleteRole(role);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            role.Name = roleName;
            dirtyRole(role);
            return Task.FromResult(0);
        }

        public Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            _roles[role.Id] = role;
            dirtyRole(role);
            return Task.FromResult(IdentityResult.Success);
        }

        Task<TRole> IRoleStore<TRole>.FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            if (_roles.ContainsKey(roleId))
            {
                return Task.FromResult(_roles[roleId]);
            }
            return Task.FromResult<TRole>(null);
        }

        Task<TRole> IRoleStore<TRole>.FindByNameAsync(string roleName, CancellationToken cancellationToken)
        {
            return
                Task.FromResult(
                    Roles.SingleOrDefault(r => String.Equals(r.NormalizedName, roleName, StringComparison.OrdinalIgnoreCase)));
        }

        public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            var claims = role.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult<IList<Claim>>(claims);
        }

        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            role.Claims.Add(new FlatFileRoleClaim<string> { ClaimType = claim.Type, ClaimValue = claim.Value, RoleId = role.Id });
            dirtyRole(role);
            return Task.FromResult(0);
        }

        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            var entity =
                role.Claims.FirstOrDefault(
                    ur => ur.RoleId == role.Id && ur.ClaimType == claim.Type && ur.ClaimValue == claim.Value);
            if (entity != null)
            {
                role.Claims.Remove(entity);
                dirtyRole(role);
            }
            return Task.FromResult(0);
        }

        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            role.NormalizedName = normalizedName;
            dirtyRole(role);
            return Task.FromResult(0);
        }

        public Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            var tokenEntity =
                user.Tokens.SingleOrDefault(
                    l =>
                        l.TokenName == name && l.LoginProvider == loginProvider &&
                        l.UserId == user.Id);
            if (tokenEntity != null)
            {
                tokenEntity.TokenValue = value;
            }
            else
            {
                user.Tokens.Add(new FlatFileUserToken
                {
                    UserId = user.Id,
                    LoginProvider = loginProvider,
                    TokenName = name,
                    TokenValue = value
                });
            }
            dirtyUser(user);
            return Task.FromResult(0);
        }

        public Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            var tokenEntity =
                user.Tokens.SingleOrDefault(
                    l =>
                        l.TokenName == name && l.LoginProvider == loginProvider &&
                        l.UserId == user.Id);
            if (tokenEntity != null)
            {
                user.Tokens.Remove(tokenEntity);
                dirtyUser(user);
            }
            return Task.FromResult(0);
        }

        public Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            var tokenEntity =
                user.Tokens.SingleOrDefault(
                    l =>
                        l.TokenName == name && l.LoginProvider == loginProvider &&
                        l.UserId == user.Id);
            return Task.FromResult(tokenEntity?.TokenValue);
        }

    }
}
