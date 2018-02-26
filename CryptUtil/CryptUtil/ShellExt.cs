using SharpShell.Attributes;
using SharpShell.SharpContextMenu;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MessageBoxExLibrary;

namespace CryptUtil {
    [ComVisible(true)]
    [COMServerAssociation(AssociationType.ClassOfExtension, ".*")]
    public class CountLinesExtension : SharpContextMenu {
        protected override bool CanShowMenu() {
            return true;
        }

        protected override ContextMenuStrip CreateMenu() {
            ContextMenuStrip menu = new ContextMenuStrip();
            
            ToolStripMenuItem itemEnc = new ToolStripMenuItem {
                Text = "[CryptUtil] Quick encrypt",
            };

            itemEnc.Click += (sender, args) => Encrypt();

            menu.Items.Add(itemEnc);

            return menu;
        }

        private void Encrypt() {
            foreach (string file in SelectedItemPaths) {
                byte[] key = new byte[16];
                new RNGCryptoServiceProvider().GetBytes(key);
                byte[] enc = Program.EncryptBytes(File.ReadAllBytes(file), key, out byte[] iv);

                File.WriteAllBytes(file, enc);

                if (enc.Length != 0) {
                    string strKey = Program.GetByteArrayAsIs(key);

                    MessageBoxEx bx = MessageBoxExManager.CreateMessageBox("success");
                    bx.AddButton("OK", "OK");
                    bx.AddButton("Copy to clipboard", "cpyclip");
                    bx.AllowSaveResponse = true;
                    bx.Text = "Key:\n" + strKey;
                    bx.Caption = $"Success: {file}!";
                    bx.Icon = MessageBoxExIcon.Information;

                    if (bx.Show() == "cpyclip")
                        Clipboard.SetText(strKey);
                } else {
                    MessageBox.Show("Error while encrypting :(", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}