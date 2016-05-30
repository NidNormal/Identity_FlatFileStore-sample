// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Identity.FlatFileStore
{
    /// <summary>
    ///     Represents a Role entity
    /// </summary>
    public class FlatFileRole : TestRole<string>
    {
        /// <summary>
        ///     Constructor
        /// </summary>
        public FlatFileRole()
        {
            Id = Guid.NewGuid().ToString();
        }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="roleName"></param>
        public FlatFileRole(string roleName) : this()
        {
            Name = roleName;
        }
    }

    /// <summary>
    ///     Represents a Role entity
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    public class TestRole<TKey> where TKey : IEquatable<TKey>
    {
        public TestRole() { }

        /// <summary>
        ///     Constructor
        /// </summary>
        /// <param name="roleName"></param>
        public TestRole(string roleName) : this()
        {
            Name = roleName;
        }

        [JsonIgnore]
        public virtual bool Changed { get; set; }

        /// <summary>
        ///     Role id
        /// </summary>
        public virtual TKey Id { get; set; }

        /// <summary>
        /// Navigation property for claims in the role
        /// </summary>
        public virtual ICollection<FlatFileRoleClaim<TKey>> Claims { get; private set; } = new List<FlatFileRoleClaim<TKey>>();

        /// <summary>
        ///     Role name
        /// </summary>
        public virtual string Name { get; set; }
        public virtual string NormalizedName { get; set; }

        /// <summary>
        /// A random value that should change whenever a role is persisted to the store
        /// </summary>
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
    }
}