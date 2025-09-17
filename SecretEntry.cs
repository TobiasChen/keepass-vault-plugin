using System;
using System.Collections.Generic;

namespace VaultSyncPlugin
{
    public class SecretEntry
    {               // stable key (KeePass UUID or Vault path)
        public Dictionary<string, string> Fields { get; set; }
        // public DateTime LastModified { get; set; }     // entry-level last modified
    }

}