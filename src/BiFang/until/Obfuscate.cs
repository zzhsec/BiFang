using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace BiFang.until
{
    public class Obfuscate
    {
        private static Random random = new Random();
        private static readonly List<string> names = new List<string>();

        public static string Random_string(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string name = "";
            do
            {
                name = new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
            } while (names.Contains(name));

            return name;
        }

        public static void Clean_asm(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    // empty method check
                    if (!method.HasBody) continue;

                    method.Body.SimplifyBranches();
                    method.Body.OptimizeBranches(); // negates simplifyBranches
                    //method.Body.OptimizeMacros();
                }
            }
        }

        public static void Obfuscate_strings(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    for (int i = 0; i < method.Body.Instructions.Count(); i++)
                    {
                        if (method.Body.Instructions[i].OpCode == OpCodes.Ldstr)
                        {
                            String regString = method.Body.Instructions[i].Operand.ToString();
                            String encString = Convert.ToBase64String(UTF8Encoding.UTF8.GetBytes(regString));
                            Console.WriteLine($"{regString} -> {encString}");

                            method.Body.Instructions[i].OpCode = OpCodes.Nop; // errors occur if instruction not replaced with Nop
                            method.Body.Instructions.Insert(i + 1, new Instruction(OpCodes.Call, md.Import(typeof(System.Text.Encoding).GetMethod("get_UTF8", new Type[] { })))); // Load string onto stack
                            method.Body.Instructions.Insert(i + 2, new Instruction(OpCodes.Ldstr, encString)); // Load string onto stack
                            method.Body.Instructions.Insert(i + 3, new Instruction(OpCodes.Call, md.Import(typeof(System.Convert).GetMethod("FromBase64String", new Type[] { typeof(string) })))); // call method FromBase64String with string parameter loaded from stack, returned value will be loaded onto stack
                            method.Body.Instructions.Insert(i + 4, new Instruction(OpCodes.Callvirt, md.Import(typeof(System.Text.Encoding).GetMethod("GetString", new Type[] { typeof(byte[]) })))); // call method GetString with bytes parameter loaded from stack
                            i += 4;
                        }
                    }
                }
            }
        }

        public static void Obfuscate_methods(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                // create method to obfuscation map
                foreach (MethodDef method in type.Methods)
                {
                    // empty method check
                    if (!method.HasBody) continue;
                    // method is a constructor
                    if (method.IsConstructor) continue;
                    // method overrides another
                    if (method.HasOverrides) continue;
                    // method has a rtspecialname, VES needs proper name
                    if (method.IsRuntimeSpecialName) continue;
                    // method foward declaration
                    if (method.DeclaringType.IsForwarder) continue;
                    Random random = new Random();
                    string encName = Random_string(random.Next(5, 11));
                    Console.WriteLine($"{method.Name} -> {encName}");
                    method.Name = encName;
                }
            }
        }

        public static void Obfuscate_classes(ModuleDef md)
        {
            foreach (var type in md.GetTypes())
            {
                Random random = new Random();
                string encName = "System." + Random_string(random.Next(5, 11));
                Console.WriteLine($"{type.Name} -> {encName}");
                type.Name = encName;
            }
        }

        public static void Run(string inFile, string outFile, bool className = false, bool Method = false, bool Variable = false)
        {
            if (inFile == "" || outFile == "") return;
            if (!className && !Method && !Variable) return;
            string pathExec = inFile;
            ModuleDef md = ModuleDefMD.Load(pathExec);
            md.Name = "MS.Internal" + Random_string(3);

            if (Variable)
                Obfuscate_strings(md);
            if (Method)
                Obfuscate_methods(md);
            if (className)
                Obfuscate_classes(md);
            Clean_asm(md);
            md.Write(outFile);
        }

        //private static void Main(string[] args)
        //{
        //    string inFile = args[0];

        //    string outFile = "";
        //    if (args.Length >= 2)
        //    {
        //        outFile = args[1];
        //    }
        //    if (outFile == "")
        //    {
        //        outFile = inFile + ".Obfuscated";
        //    }
        //    Run(inFile, outFile);
        //}
    }
}