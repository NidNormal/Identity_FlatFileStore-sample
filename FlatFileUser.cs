// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Identity.FlatFileStore
{
    public class FlatFileUser : FlatFileUser<string>
    {
        public FlatFileUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public FlatFileUser(string userName) : this()
        {
            UserName = userName;
        }
    }

    public class FlatFileUser<TKey> where TKey : IEquatable<TKey>
    {
        public FlatFileUser() { }

        public FlatFileUser(string userName) : this()
        {
            UserName = userName;
        }

        [JsonIgnore]
        public virtual bool Changed { get; set; }
        public virtual TKey Id { get; set; }
        public virtual string UserName { get; set; }
        public virtual string NormalizedUserName { get; set; }

        /// <summary>
        ///     Email
        /// </summary>
        public virtual string Email { get; set; }

        public virtual string NormalizedEmail { get; set; }

        /// <summary>
        ///     True if the email is confirmed, default is false
        /// </summary>
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        ///     The salted/hashed form of the user password
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        /// A random value that should change whenever a users credentials change (password changed, login removed)
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        /// A random value that should change whenever a user is persisted to the store
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        ///     PhoneNumber for the user
        /// </summary>
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        ///     True if the phone number is confirmed, default is false
        /// </summary>
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        ///     Is two factor enabled for the user
        /// </summary>
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        ///     DateTime in UTC when lockout ends, any time in the past is considered not locked out.
        /// </summary>
        public virtual DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>
        ///     Is lockout enabled for this user
        /// </summary>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        ///     Used to record failures for the purposes of lockout
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        public virtual ICollection<FlatFileUserRole<TKey>> Roles { get; private set; } = new List<FlatFileUserRole<TKey>>();
        public virtual ICollection<FlatFileUserClaim<TKey>> Claims { get; private set; } = new List<FlatFileUserClaim<TKey>>();
        public virtual ICollection<FlatFileUserLogin> Logins { get; private set; } = new List<FlatFileUserLogin>();
        public virtual ICollection<FlatFileUserToken<TKey>> Tokens { get; private set; } = new List<FlatFileUserToken<TKey>>();
    }
}
