public static void CheckHardDiskSpace()
    {
        string diskName = Environment.GetLogicalDrives()[0];
        long totalSize = new long();
        System.IO.DriveInfo[] drives = System.IO.DriveInfo.GetDrives();
        foreach (System.IO.DriveInfo drive in drives)
        {
            if (drive.Name == diskName)
            {
                totalSize = drive.TotalSize;
            }
        }
        totalSize = totalSize / (1024 * 1024 * 1024);
        if (totalSize < 50)
        {
            Environment.Exit(-1);
        }
    }