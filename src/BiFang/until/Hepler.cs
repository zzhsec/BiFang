using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BiFang.until
{
   public class Hepler
    {
        public static void PrintError(string error)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(error);
            Console.ResetColor();
        }

        public static void PrintSuccess(string success)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(success);
            Console.ResetColor();
        }
        
        public static  Dictionary<string, string>Analysis(string[] args)
        {
            var arguments = new Dictionary<string, string>();

            foreach (var argument in args)
            {
                var idx = argument.IndexOf(':');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
                else
                    arguments[argument] = string.Empty;
            }

            return arguments;
        }

        public static void help()
        {
            throw new NotImplementedException();
        }
    }
}
