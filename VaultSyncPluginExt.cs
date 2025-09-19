/*
  SamplePlugin - An Example KeePass Plugin
  Copyright (C) 2003-2019 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.Resources;
using KeePass.UI;
using KeePass.Util.Spr;
using KeePassLib;
using KeePassLib.Security;
using KeePassLib.Utility;
using VaultSyncPlugin;
using Vault;
using Vault.Client;
using Vault.Model;


// The namespace name must be the same as the file name of the
// plugin without its extension.
// For example, if you compile a plugin 'SamplePlugin.dll',
// the namespace must be named 'SamplePlugin'.
namespace VaultSyncPlugin
{
    // Namespace name 'SamplePlugin' + 'Ext' = 'SamplePluginExt'
    public sealed class VaultSyncPluginExt : Plugin
    {
        // The plugin remembers its host in this variable
        private IPluginHost host = null;
        private ToolStripSeparator separator;
        private ToolStripMenuItem menuItem;
        private SyncStatus syncStatus;
        private SyncStatusForm syncStatusForm;
        
        
        private String groupName = "Vault-Sync";

        /// <summary>
        /// The <c>Initialize</c> method is called by KeePass when
        /// you should initialize your plugin.
        /// </summary>
        /// <param name="host">Plugin host interface. Through this
        /// interface you can access the KeePass main window, the
        /// currently opened database, etc.</param>
        /// <returns>You must return <c>true</c> in order to signal
        /// successful initialization. If you return <c>false</c>,
        /// KeePass unloads your plugin (without calling the
        /// <c>Terminate</c> method of your plugin).</returns>
        public override bool Initialize(IPluginHost host)
        {
            if (host == null) return false; // Fail; we need the host
            this.host = host;

            var menuItemCollection = this.host.MainWindow.ToolsMenu.DropDownItems;
            this.separator = new ToolStripSeparator();
            menuItemCollection.Add(this.separator);

            // Add menu item
            this.menuItem = new ToolStripMenuItem();
            this.menuItem.Text = "Synchronize Vault entries";
            this.menuItem.Click += this.OnMenuItemClick;
            menuItemCollection.Add(this.menuItem);

            this.syncStatus = new SyncStatus();

            // We want a notification when the user tried to save
            // the current database
            this.host.MainWindow.FileSaved += this.OnFileSaved;

            return true; // Initialization successful
        }

        /// <summary>
        /// The <c>Terminate</c> method is called by KeePass when
        /// you should free all resources, close files/streams,
        /// remove event handlers, etc.
        /// </summary>
        public override void Terminate()
        {
            // Save the state of the 30 entries option
            ToolStripItemCollection menuItemCollection = this.host.MainWindow.ToolsMenu.DropDownItems;
            this.menuItem.Click -= this.OnMenuItemClick;
            menuItemCollection.Remove(this.menuItem);
            menuItemCollection.Remove(this.separator);

            // Unsubscribe from file opened event
            this.host.MainWindow.FileOpened -= this.OnFileOpened;

            base.Terminate();

            // Remove event handler (important!)
            host.MainWindow.FileSaved -= this.OnFileSaved;
        }

        // /// <summary>
        // /// Get a menu item of the plugin. See
        // /// https://keepass.info/help/v2_dev/plg_index.html#co_menuitem
        // /// </summary>
        // /// <param name="t">Type of the menu that the plugin should
        // /// return an item for.</param>
        // public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        // {
        // 	// Our menu item below is intended for the main location(s),
        // 	// not for other locations like the group or entry menus
        // 	if(t != PluginMenuType.Main) return null;
        //
        // 	ToolStripMenuItem tsmi = new ToolStripMenuItem("VaultSyncPlugin");
        //
        // 	// Add menu item 'Add Some Groups'
        // 	ToolStripMenuItem tsmiAddGroups = new ToolStripMenuItem();
        // 	tsmiAddGroups.Text = "Add Some Groups";
        // 	tsmiAddGroups.Click += this.OnMenuAddGroups;
        // 	tsmi.DropDownItems.Add(tsmiAddGroups);
        //
        // 	// Add menu item 'Add Some Entries'
        // 	ToolStripMenuItem tsmiAddEntries = new ToolStripMenuItem();
        // 	tsmiAddEntries.Text = "Add Some Entries";
        // 	tsmiAddEntries.Click += this.OnMenuAddEntries;
        // 	tsmi.DropDownItems.Add(tsmiAddEntries);
        //
        // 	tsmi.DropDownItems.Add(new ToolStripSeparator());
        //
        // 	ToolStripMenuItem tsmiEntries30 = new ToolStripMenuItem();
        // 	tsmiEntries30.Text = "Add 30 Entries Instead Of 10";
        // 	tsmiEntries30.Click += this.OnMenuEntries30;
        // 	tsmi.DropDownItems.Add(tsmiEntries30);
        //
        // 	// By using an anonymous method as event handler, we do not
        // 	// need to remember menu item references manually, and
        // 	// multiple calls of the GetMenuItem method (to show the
        // 	// menu item in multiple places) are no problem
        // 	tsmi.DropDownOpening += delegate(object sender, EventArgs e)
        // 	{
        // 		// Disable the commands 'Add Some Groups' and
        // 		// 'Add Some Entries' when the database is not open
        // 		PwDatabase pd = host.Database;
        // 		bool bOpen = ((pd != null) && pd.IsOpen);
        // 		tsmiAddGroups.Enabled = bOpen;
        // 		tsmiAddEntries.Enabled = bOpen;
        //
        // 		// Update the checkmark of the menu item
        // 		UIUtil.SetChecked(tsmiEntries30, m_bEntries30);
        // 	};
        //
        // 	return tsmi;
        // }

        /// <summary>
        /// Called when menu item is clicked.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event args</param>
        private void OnMenuItemClick(object sender, EventArgs e)
        {
            this.SyncWithVault();
        }

        /// <summary>
        /// Called when file is opened so we can check vault entries in it.
        /// </summary>
        /// <param name="sender">The sender.</param>
        /// <param name="e">The event args</param>
        private void OnFileOpened(object sender, FileOpenedEventArgs e)
        {
            this.SyncWithVault();
        }


        /// <summary>
        /// Do the stuff needed. Single entry point for the plugin to do its work.
        /// </summary>
        private void SyncWithVault()
        {
            if (this.syncStatusForm == null)
            {
                this.syncStatusForm = new SyncStatusForm(this.syncStatus);
            }

            Init();

            this.syncStatusForm.Show();

            Task.Run(() =>
            {
                this.syncStatus.StartSync();

                // We synchronize vault entries
                // this.SynchronizeVaultEntries(this.host.Database.RootGroup);
                var vaultGroup = getVaultGroup();
                var validList = FindEntriesWithVaultConnectionInGroup(vaultGroup);
                foreach (var pwconnectionString in validList)
                {
                    SyncVaultInstance(pwconnectionString, vaultGroup);
                }

                // Then we merge modified data, and refresh the UI. Standard way to do it, but barely documented.
                host.Database.MergeIn(this.host.Database, PwMergeMethod.Synchronize);

                ExecuteInGuiThread(new Action(() => { this.host.MainWindow.UpdateUI(false, null, true, this.host.Database.RootGroup, true, null, true); }));

                // NOTE: We don't automatically save the database

                this.syncStatus.StopSync();
            });
        }

        private PwGroup getVaultGroup()
        {

            return host.Database.RootGroup.Groups.ToList().Find(x => x.Name.Equals(groupName));
        }

        private List<PwEntry> FindEntriesWithVaultConnectionInGroup(PwGroup group)
        {
            var validList = group.Entries.ToList().FindAll(entry =>
            {
                var vaultLogin = this.GetKeepassEntryPropertyDereferenced(entry, PwDefs.UserNameField);
                var vaultPassword = this.GetKeepassEntryPropertyDereferenced(entry, PwDefs.PasswordField);
                var vaultUrl = this.GetKeepassEntryPropertyDereferenced(entry, PwDefs.UrlField);
                // var vaultAuthPath = this.GetKeepassEntryProperty(entry, "auth");
                // var vaultPath = this.GetKeepassEntryProperty(entry, "path");
                return !string.IsNullOrEmpty(vaultUrl) &&
                       !string.IsNullOrEmpty(vaultLogin) &&
                       !string.IsNullOrEmpty(vaultPassword); // &&
                // !string.IsNullOrEmpty(vaultPath) &&
                // !string.IsNullOrEmpty(vaultAuthPath);
            });
            Console.WriteLine("Found {0} valid Connection Strings", validList.Count);
            return validList;
        }
        // Make sure Vault connection is established and folders exist
        private void Init()
        {

            var vaultGroup = getVaultGroup();
            if (vaultGroup == null)
            {
                Console.WriteLine("Vault Group Folder couldn't be found: Creating");
                host.Database.RootGroup.AddGroup(new PwGroup(true, true, groupName, host.Database.RootGroup.IconId), true);

                SaveAndUpdateUI();
                vaultGroup = host.Database.RootGroup.Groups.First(x => x.Name.Equals(groupName));
            }

            //Try to find at least one Vault-Connection Secret;

            var validList = FindEntriesWithVaultConnectionInGroup(vaultGroup);
            if (validList.Count == 0)
            {
                MessageService.ShowInfo("Please fill in the created Secret with the vault URL, Username and Password");
                var vaultEntry = new PwEntry(false, true);
                vaultEntry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "First Vault"));
                vaultGroup.Entries.Add(vaultEntry);
                // SaveAndUpdateUI();

                return;
            }

            foreach (PwEntry entry in validList)
            {
                var entryName = GetKeepassEntryPropertyDereferenced(entry, PwDefs.TitleField);
                //Ensure Folder exists in Database

                var groupForPassword = vaultGroup.Groups.ToList().Find(x =>
                    x.Name.Equals(entryName));
                if (groupForPassword == null)
                {
                    Console.WriteLine("No Folder for connection string {0} found, creating", entryName);
                    vaultGroup.AddGroup(new PwGroup(true, true, entryName, host.Database.RootGroup.IconId), true);
                    SaveAndUpdateUI();
                }
                
            }
        }

        private async void SyncVaultInstance(PwEntry entry, PwGroup vaultGroup)
        {
            var user = GetKeepassEntryPropertyDereferenced(entry, PwDefs.UserNameField);
            var pass = GetKeepassEntryPropertyDereferenced(entry, PwDefs.PasswordField);
            var url = GetKeepassEntryPropertyDereferenced(entry, PwDefs.UrlField);
            var mountPath = GetKeepassEntryPropertyDereferenced(entry, "MountPath");
            var vaultFolder = GetKeepassEntryPropertyDereferenced(entry, "VaultFolder");
            VaultConfiguration config = new VaultConfiguration(url,
                rateLimitConfiguration: new RateLimitConfiguration(1000, TimeSpan.FromMilliseconds(1)));
            VaultClient vaultClient = new VaultClient(config);

            var vaultResponse = vaultClient.Auth.UserpassLogin(
                username: user,
                userpassLoginRequest: new UserpassLoginRequest(pass),
                userpassMountPath: "userpass");
            // VaultResponse<Object> unwrappedResp = vaultClient.Unwrap<Object>(vaultResponse.ResponseWrapInfo.Token);
            vaultClient.SetToken(token: vaultResponse.ResponseAuth.ClientToken);
            var groupForPassword = vaultGroup.Groups.ToList().Find(x =>
                x.Name.Equals( GetKeepassEntryPropertyDereferenced(entry, PwDefs.TitleField)));
            
            var keepassDict = KeePassDictionaryBuilder.Build(groupForPassword);
            var vaultDict = await VaultDictionaryBuilder.BuildAsync(vaultClient,  mountPath, vaultFolder);
            // 4. Sync (KeePass -> Vault) with change detection
            var syncer = new OneWaySyncer(vaultClient, mountPath);
            await syncer.SyncAsync(keepassDict, vaultDict);
        }

        private void SaveAndUpdateUI()
        {
            this.host.Database.MergeIn(this.host.Database, PwMergeMethod.Synchronize);
            this.ExecuteInGuiThread(new Action(() =>
            {
                this.host.MainWindow.UpdateUI(false, null, true, this.host.Database.RootGroup, true, null, true);
            }));
        }

        /// <summary>
        /// Helper method to get keepass entry property as string, following references
        /// </summary>
        /// <param name="entry">The keepass entry</param>
        /// <param name="field">The field</param>
        /// <returns>The dereferenced value for this field.</returns>
        private string GetKeepassEntryPropertyDereferenced(PwEntry entry, string field)
        {
            var value = this.GetKeepassEntryProperty(entry, field);
            this.ExecuteInGuiThread(new Action(() =>
            {
                value = SprEngine.Compile(value, new SprContext(entry, this.host.Database, SprCompileFlags.All));
            }));
            return value;
        }

        /// <summary>
        /// Helper method to get keepass entry property as string
        /// </summary>
        /// <param name="entry">The keepass entry</param>
        /// <param name="field">The field</param>
        /// <returns>The value for this field.</returns>
        private string GetKeepassEntryProperty(PwEntry entry, string field)
        {
            return entry.Strings.GetSafe(field).ReadString();
        }

        /// <summary>
        /// Execute a delegate in the GUI thread when manipulating GUI objects
        /// </summary>
        /// <param name="delegate">The delegate to execute</param>
        private void ExecuteInGuiThread(Delegate @delegate)
        {
            if (this.host.MainWindow.InvokeRequired)
            {
                this.host.MainWindow.Invoke(@delegate);
            }
            else
            {
                @delegate.DynamicInvoke();
            }
        }

        private void OnFileSaved(object sender, FileSavedEventArgs e)
        {
            // MessageService.ShowInfo("SamplePlugin has been notified that the user tried to save to the following file:",
            // 	e.Database.IOConnectionInfo.Path, "Result: " +
            // 	(e.Success ? "success." : "failed."));
        }
    }
}