 public static void CheckMACAddress()
    {
        string[] blacklist = { "000569", "000C29", "001C14", "005056", "080027" };
        NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
        var mac = nics[0].GetPhysicalAddress().ToString();
        foreach (var name in blacklist)
        {
            if (mac.Contains(name))
            {
                Environment.Exit(-1);
            }
        }
    }