using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Vault;
using Vault.Model;

namespace VaultSyncPlugin
{
    public class OneWaySyncer
    {
        private readonly VaultClient _vault;
        private readonly string _mount;


        public OneWaySyncer(VaultClient vault, string mount)
        {
            _vault = vault;
            _mount = mount;
        }

        public async Task SyncAsync(
            Dictionary<string, SecretEntry> keePassDict,
            Dictionary<string, SecretEntry> vaultDict,
            SyncStatus syncStatus)
        {
            // 1️⃣  Create or update only if fields differ
            foreach (KeyValuePair<string, SecretEntry> entry in keePassDict)
            {
                SecretEntry existing;
                if (!vaultDict.TryGetValue(entry.Key, out existing)
                    || !FieldsEqual(existing.Fields, entry.Value.Fields))
                {
                    syncStatus.AddLog("Adding secrets to Vault: " + entry.Key);
                    await _vault.Secrets.KvV2WriteAsync(entry.Key, kvV2WriteRequest: new KvV2WriteRequest(Data: entry.Value.Fields), kvV2MountPath: _mount);
                }
            }

            // 2️⃣  Delete anything in Vault not in KeePass
            foreach (var stale in vaultDict.Keys.Except(keePassDict.Keys))
            {
                syncStatus.AddLog("Deleting stale secret from Vault: " + stale);
                await _vault.Secrets.KvV2DeleteMetadataAndAllVersionsAsync( path:stale, kvV2MountPath: _mount);
            }
        }

        private static bool FieldsEqual(
            Dictionary<string, string> a,
            Dictionary<string, string> b)
        {
            if (a.Count != b.Count) return false;
            foreach (var kv in a)
            {
                String bv;
                if (!b.TryGetValue(kv.Key, out bv) || kv.Value != bv)
                    return false;
            }

            return true;
        }
    }
}