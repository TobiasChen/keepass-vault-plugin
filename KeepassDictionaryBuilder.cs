using System;
using System.Collections.Generic;
using KeePassLib;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace VaultSyncPlugin
{
    public static class KeePassDictionaryBuilder
    {
        public static Dictionary<string, SecretEntry> Build(PwGroup vaultGroup)
        {
            var dict = new Dictionary<string, SecretEntry>();
            TraverseGroup(vaultGroup, "", dict);
            return dict;
        }

        private static void TraverseGroup(PwGroup group, string prefix, Dictionary<string, SecretEntry> dict)
        {
            string current = string.IsNullOrEmpty(prefix) ? "" : prefix + "/";
            foreach (var e in group.Entries)
            {
                var path = current + e.Strings.ReadSafe("Title");
                var fields = new Dictionary<String, String>();
                foreach (var field in e.Strings.GetKeys())
                {
                    fields[field] = e.Strings.ReadSafe(field);
                }
                
                dict[path] = new SecretEntry
                {
                    Fields = fields
                };
            }

            foreach (var sub in group.Groups)
                TraverseGroup(sub, current + sub.Name, dict);
        }
    }
}