public static void CheckStartTime()
    {
        var time = System.Environment.TickCount;
        if (time < 3600000)
        {
            Environment.Exit(-1);
        }
    }