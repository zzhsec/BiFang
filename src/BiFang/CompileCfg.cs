using System.Collections.Generic;

namespace BiFang
{
    public class Sandbox
    {
        public string UIName { get; set; }
        public string Path { get; set; }

        public string Methmod { get; set; }
        public string MethmodRun { get; set; }
    }

    public class Teach
    {
        public string DisplayName { get; set; }
        public string Path { get; set; }
    }

    public class CompileCfg
    {
        public string SourceCode { get; set; }
        public string HTTPRaw { get; set; }
        public string DNSRaw { get; set; }
        public List<Sandbox> Sandboxes { get; set; }
        public string Key { get; set; }
        public string Salt { get; set; }

        public string Outpath { get; set; } = "scvhost.exe";
    }
}