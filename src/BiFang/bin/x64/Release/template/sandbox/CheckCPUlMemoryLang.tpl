  public static void CheckCPUlMemoryLang()
    {
        int processorCount = Environment.ProcessorCount;
        string Lang = Thread.CurrentThread.CurrentCulture.Name;
        if (processorCount < 4 || Lang != "zh-CN")
        {
            Environment.Exit(-1);
        }

    }