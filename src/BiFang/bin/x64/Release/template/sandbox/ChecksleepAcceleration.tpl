 public static void ChecksleepAcceleration()
    {
        int first = DateTime.Now.Minute;
        Thread.Sleep(120000);
        int second = DateTime.Now.Minute;
        if (second - first != 3)
        {
            Environment.Exit(-1);
        }
    }