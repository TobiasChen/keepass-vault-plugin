using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Vault;
using Vault.Client;
using Newtonsoft.Json;

namespace VaultSyncPlugin
{
    public static class VaultDictionaryBuilder
    {
        public static async Task<Dictionary<string, SecretEntry>> BuildAsync(
            VaultClient client, string mount, string prefix)
        {
            var dict = new Dictionary<string, SecretEntry>();
            await TraverseVault(client, mount, prefix, dict);
            return dict;
        }

        private static async Task TraverseVault(VaultClient client, string mount,
            string path, Dictionary<string, SecretEntry> dict)
        {
            var listResp = await client.Secrets.KvV2ListAsync(path, mount);
            if (listResp.Data.Keys == null) return;

            foreach (var key in listResp.Data.Keys)
            {
                if (key.EndsWith("/"))
                {
                    await TraverseVault(client, mount,
                        string.IsNullOrEmpty(path) ? key.TrimEnd('/') : string.Format("{0}/{1}", path, key.TrimEnd('/')), dict);
                }
                else
                {
                    string fullPath = string.IsNullOrEmpty(path) ? key :string.Format("{0}/{1}", path, key);
                    var secret = await client.Secrets.KvV2ReadAsync(fullPath, mount);
                    // var meta = await client.Secrets.KvV2ReadMetadataAsync(fullPath,mount);
                    dict[fullPath] = new SecretEntry
                    {
                        Fields = JsonConvert.DeserializeObject<Dictionary<String, String>>(secret.Data.Data.ToString())
                    };
                }
            }
        }
    }
}