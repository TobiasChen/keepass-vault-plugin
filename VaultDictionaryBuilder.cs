using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading.Tasks;
using Vault;
using Vault.Client;
using Newtonsoft.Json;
using Vault.Model;

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
            Console.WriteLine(@"Reading secrets from {0}/{1}", mount, path);
            VaultResponse<StandardListResponse> listResp;
            try
            {
                 listResp = await client.Secrets.KvV2ListAsync(path, mount);
            }
            catch (VaultApiException e)
            {
                if(e.StatusCode == 404) return;
                throw;
                
            }

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
                    Console.WriteLine(@"Found Secret at {0}/{1}", mount, fullPath);
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