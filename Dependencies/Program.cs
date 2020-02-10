using System;
using System.Collections.Generic;
using System.Xml.Linq;
using System.IO;
using System.Linq;
using System.Diagnostics;

using NDesk.Options;
using Newtonsoft.Json;
using Dependencies.ClrPh;

namespace Dependencies
{
    interface IPrintable
    {
        void PrettyPrint();
        void CleanPrint();
    }

    /// <summary>
    /// Printable KnownDlls object
    /// </summary>
    class NtKnownDlls : IPrintable
    {
        public NtKnownDlls()
        {
            x64 = Phlib.GetKnownDlls(false);
            x86 = Phlib.GetKnownDlls(true);
        }

        public void PrettyPrint()
        {
            Console.WriteLine("[-] 64-bit KnownDlls : ");

            string System32Folder = Environment.GetFolderPath(Environment.SpecialFolder.System);
            foreach (String KnownDll in this.x64)
            {
                Console.WriteLine("  {0:s}\\{1:s}", System32Folder, KnownDll);
            }

            Console.WriteLine("");

            Console.WriteLine("[-] 32-bit KnownDlls : ");

            string SysWow64Folder = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            foreach (String KnownDll in this.x86)
            {
                Console.WriteLine("  {0:s}\\{1:s}", SysWow64Folder, KnownDll);
            }


            Console.WriteLine("");
        }

        public void CleanPrint()
        {
            string System32Folder = Environment.GetFolderPath(Environment.SpecialFolder.System);
            foreach (String KnownDll in this.x64)
            {
                Console.WriteLine(System32Folder, KnownDll);
            }
            string SysWow64Folder = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            foreach (String KnownDll in this.x86)
            {
                Console.WriteLine(SysWow64Folder, KnownDll);
            }
        }

        public List<String> x64;
        public List<String> x86;
    }

    /// <summary>
    /// Printable ApiSet schema object
    /// </summary>
    class NtApiSet : IPrintable
    {
        public NtApiSet()
        {
            Schema = Phlib.GetApiSetSchema();
        }

        public NtApiSet(PE ApiSetSchemaDll)
        {
            Schema = ApiSetSchemaDll.GetApiSetSchema();
        }

        public void PrettyPrint()
        {
            Console.WriteLine("[-] Api Sets Map : ");

            foreach (var ApiSetEntry in this.Schema.GetAll())
            {
                ApiSetTarget ApiSetImpl = ApiSetEntry.Value;
                string ApiSetName = ApiSetEntry.Key;
                string ApiSetImplStr = (ApiSetImpl.Count > 0) ? String.Join(",", ApiSetImpl.ToArray()) : "";

                Console.WriteLine("{0:s} -> [ {1:s} ]", ApiSetName, ApiSetImplStr);
            }

            Console.WriteLine("");
        }
        public void CleanPrint()
        {
            foreach (var ApiSetEntry in this.Schema.GetAll())
            {
                ApiSetTarget ApiSetImpl = ApiSetEntry.Value;
                string ApiSetName = ApiSetEntry.Key;
                string ApiSetImplStr = (ApiSetImpl.Count > 0) ? String.Join(",", ApiSetImpl.ToArray()) : "";

                Console.WriteLine(ApiSetName, ApiSetImplStr);
            }
        }

        public ApiSetSchema Schema;
    }


    class PEManifest : IPrintable
    {

        public PEManifest(PE _Application)
        {
            Application = _Application;
            Manifest = Application.GetManifest();
            XmlManifest = null;
            Exception = "";

            if (Manifest.Length != 0)
            {
                try
                {
                    // Use a memory stream to correctly handle BOM encoding for manifest resource
                    using (var stream = new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(Manifest)))
                    {
                        XmlManifest = SxsManifest.ParseSxsManifest(stream);
                    }


                }
                catch (System.Xml.XmlException e)
                {
                    //Console.Error.WriteLine("[x] \"Malformed\" pe manifest for file {0:s} : {1:s}", Application.Filepath, PeManifest);
                    //Console.Error.WriteLine("[x] Exception : {0:s}", e.ToString());
                    XmlManifest = null;
                    Exception = e.ToString();
                }
            }
        }


        public void PrettyPrint()
        {
            Console.WriteLine("[-] Manifest for file : {0}", Application.Filepath);

            if (Manifest.Length == 0)
            {
                Console.WriteLine("[x] No embedded pe manifest for file {0:s}", Application.Filepath);
                return;
            }

            if (Exception.Length != 0)
            {
                Console.Error.WriteLine("[x] \"Malformed\" pe manifest for file {0:s} : {1:s}", Application.Filepath, Manifest);
                Console.Error.WriteLine("[x] Exception : {0:s}", Exception);
                return;
            }

            Console.WriteLine(XmlManifest);
        }
        public void CleanPrint()
        {
            if (Manifest.Length == 0)
            {
                return;
            }
            if (Exception.Length != 0)
            {
                return;
            }
            Console.WriteLine(XmlManifest);
        }

        public string Manifest;
        public XDocument XmlManifest;

        // stays private in order not end up in the json output
        private PE Application;
        private string Exception;
    }

    class PEImports : IPrintable
    {
        public PEImports(PE _Application)
        {
            Application = _Application;
            Imports = Application.GetImports();
        }

        public void PrettyPrint()
        {
            Console.WriteLine("[-] Import listing for file : {0}", Application.Filepath);

            foreach (PeImportDll DllImport in Imports)
            {
                Console.WriteLine("Import from module {0:s} :", DllImport.Name);

                foreach (PeImport Import in DllImport.ImportList)
                {
                    if (Import.ImportByOrdinal)
                    {
                        Console.Write("\t Ordinal_{0:d} ", Import.Ordinal);
                    }
                    else
                    {
                        Console.Write("\t Function {0:s}", Import.Name);
                    }
                    if (Import.DelayImport)
                        Console.WriteLine(" (Delay Import)");
                    else
                        Console.WriteLine("");
                }
            }

            Console.WriteLine("[-] Import listing done");
        }
        public void CleanPrint()
        {
            foreach (PeImportDll DllImport in Imports)
            {
                Console.WriteLine(DllImport.Name);

                foreach (PeImport Import in DllImport.ImportList)
                {
                    if (Import.ImportByOrdinal)
                    {
                        Console.Write("\t;{0:d}", Import.Ordinal);
                    }
                    else
                    {
                        Console.Write("\t;{0:s}", Import.Name);
                    }
                }
            }
        }

        public List<PeImportDll> Imports;
        private PE Application;
    }

    class PEExports : IPrintable
    {
        public PEExports(PE _Application)
        {
            Application = _Application;
            Exports = Application.GetExports();
        }

        public void PrettyPrint()
        {
            Console.WriteLine("[-] Export listing for file : {0}", Application.Filepath);

            foreach (PeExport Export in Exports)
            {
                Console.WriteLine("Export {0:d} :", Export.Ordinal);
                Console.WriteLine("\t Name : {0:s}", Export.Name);
                Console.WriteLine("\t VA : 0x{0:X}", (int)Export.VirtualAddress);
                if (Export.ForwardedName.Length > 0)
                    Console.WriteLine("\t ForwardedName : {0:s}", Export.ForwardedName);
            }

            Console.WriteLine("[-] Export listing done");
        }
        public void CleanPrint()
        {
            foreach (PeExport Export in Exports)
            {
                Console.WriteLine(Export.Ordinal);
                Console.Write("\t;{0:s}", Export.Name);
                Console.Write("\t;{0:X}", (int)Export.VirtualAddress);
                if (Export.ForwardedName.Length > 0)
                    Console.Write("\t;{0:s}", Export.ForwardedName);
            }
        }

        public List<PeExport> Exports;
        private PE Application;
    }


    class SxsDependencies : IPrintable
    {
        public SxsDependencies(PE _Application)
        {
            Application = _Application;
            SxS = SxsManifest.GetSxsEntries(Application);
        }

        public void PrettyPrint()
        {
            Console.WriteLine("[-] sxs dependencies for executable : {0}", Application.Filepath);
            foreach (SxsEntry entry in SxS)
            {
                if (entry.Path.Contains("???"))
                {
                    Console.WriteLine("  [x] {0:s} : {1:s}", entry.Name, entry.Path);
                }
                else
                {
                    Console.WriteLine("  [+] {0:s} : {1:s}", entry.Name, Path.GetFullPath(entry.Path));
                }
            }
        }

        public void CleanPrint()
        {
            foreach (SxsEntry entry in SxS)
            {
                if (entry.Path.Contains("???"))
                {
                    Console.WriteLine(entry.Path);
                }
                else
                {
                    Console.WriteLine(Path.GetFullPath(entry.Path));
                }
            }
        }

        public SxsEntries SxS;
        private PE Application;

    }


    // Basic custom exception used to be able to differentiate between a "native" exception
    // and one that has been already catched, processed and rethrown
    public class RethrownException : Exception
    {
        public RethrownException(Exception e)
        : base(e.Message, e.InnerException)
        {
        }

    }


    class PeDependencyItem : IPrintable
    {

        public PeDependencyItem(PeDependencies _Root, string _ModuleName, string ModuleFilepath, ModuleSearchStrategy Strategy, int Level)
        {
            Action action = () =>
            {
                Root = _Root;
                ModuleName = _ModuleName;


                Imports = new List<PeImportDll>();
                Filepath = ModuleFilepath;
                SearchStrategy = Strategy;
                RecursionLevel = Level;

                DependenciesResolved = false;
                Dependencies = new List<PeDependencyItem>();
                ResolvedImports = new List<PeDependencyItem>();
            };

            SafeExecutor(action);
        }

        public void LoadPe()
        {
            Action action = () =>
            {
                if (Filepath != null)
                {
                    PE Module = BinaryCache.LoadPe(Filepath);
                    Imports = Module.GetImports();
                }
                else
                {
                    //Module = null;
                }
            };

            SafeExecutor(action);
        }

        public void ResolveDependencies()
        {
            Action action = () =>
            {
                if (DependenciesResolved)
                {
                    return;
                }


                foreach (PeImportDll DllImport in Imports)
                {
                    string ModuleFilepath = null;
                    ModuleSearchStrategy Strategy;


                    // Find Dll in "paths"
                    Tuple<ModuleSearchStrategy, PE> ResolvedModule = Root.ResolveModule(DllImport.Name, Root.CustomSearchFolders, Root.IgnoreSearchStrategies);
                    Strategy = ResolvedModule.Item1;

                    if (Strategy != ModuleSearchStrategy.NOT_FOUND)
                    {
                        ModuleFilepath = ResolvedModule.Item2?.Filepath;
                    }



                    bool IsAlreadyCached = Root.isModuleCached(DllImport.Name, ModuleFilepath);
                    PeDependencyItem DependencyItem = Root.GetModuleItem(DllImport.Name, ModuleFilepath, Strategy, RecursionLevel + 1);

                    // do not add twice the same imported module
                    if (ResolvedImports.Find(ri => ri.ModuleName == DllImport.Name) == null)
                    {
                        ResolvedImports.Add(DependencyItem);
                    }

                    // Do not process twice a dependency. It will be displayed only once
                    if (!IsAlreadyCached)
                    {
                        Debug.WriteLine("[{0:d}] [{1:s}] Adding dep {2:s}", RecursionLevel, ModuleName, ModuleFilepath);
                        Dependencies.Add(DependencyItem);
                    }

                }

                DependenciesResolved = true;
                if ((Root.MaxRecursion > 0) && ((RecursionLevel + 1) >= Root.MaxRecursion))
                {
                    return;
                }


                // Recursively resolve dependencies
                foreach (var Dep in Dependencies)
                {
                    Dep.LoadPe();
                    Dep.ResolveDependencies();
                }
            };

            SafeExecutor(action);
        }

        public void PrettyPrint()
        {
            string Tabs = string.Concat(Enumerable.Repeat("|  ", RecursionLevel));
            Console.WriteLine("{0:s}├ {1:s} ({2:s}) : {3:s} ", Tabs, ModuleName, SearchStrategy.ToString(), Filepath);

            foreach (var Dep in ResolvedImports)
            {
                bool NeverSeenModule = Root.VisitModule(Dep.ModuleName, Dep.Filepath);

                if (NeverSeenModule)
                {
                    Dep.PrettyPrint();
                }
                else
                {
                    Dep.BasicPrettyPrint();
                }

            }
        }

        public void BasicPrettyPrint()
        {
            string Tabs = string.Concat(Enumerable.Repeat("|  ", RecursionLevel));
            Console.WriteLine("{0:s}├ {1:s} ({2:s}) : {3:s} ", Tabs, ModuleName, SearchStrategy.ToString(), Filepath);
        }

        public void CleanPrint()
        {
            foreach (var Dep in ResolvedImports)
            {
                bool NeverSeenModule = Root.VisitModule(Dep.ModuleName, Dep.Filepath);

                if (NeverSeenModule)
                {
                    Dep.CleanPrint();
                }
                else
                {
                    if ((Root.PrintFoundOrNot && Dep.SearchStrategy != ModuleSearchStrategy.NOT_FOUND) || (!Root.PrintFoundOrNot && Dep.SearchStrategy == ModuleSearchStrategy.NOT_FOUND))
                    {
                        Console.WriteLine(Filepath);
                    }
                }

            }
        }

        private void SafeExecutor(Action action)
        {
            SafeExecutor(() => { action(); return 0; });
        }

        private T SafeExecutor<T>(Func<T> action)
        {
            try
            {
                return action();
            }
            catch (RethrownException rex)
            {
                Console.Error.WriteLine(" - \"{0:s}\"", Filepath);
                throw rex;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Unhandled exception occured while processing \"{1:s}\"", RecursionLevel, Filepath);
                Console.Error.WriteLine("Stacktrace:\n{0:s}\n", ex.StackTrace);
                Console.Error.WriteLine("Modules backtrace:");
                throw new RethrownException(ex);
            }
            finally
            {
                //

            }

            return default(T);
        }

        public string ModuleName;
        public string Filepath;
        public ModuleSearchStrategy SearchStrategy;
        public List<PeDependencyItem> Dependencies;

        protected List<PeDependencyItem> ResolvedImports;
        protected List<PeImportDll> Imports;
        protected PeDependencies Root;
        protected int RecursionLevel;

        private bool DependenciesResolved;
    }


    class ModuleCacheKey : Tuple<string, string>
    {
        public ModuleCacheKey(string Name, string Filepath)
        : base(Name, Filepath)
        {
        }
    }

    class ModuleEntries : Dictionary<ModuleCacheKey, PeDependencyItem>, IPrintable
    {
        public void PrettyPrint()
        {
            foreach (var item in this.Values.OrderBy(module => module.SearchStrategy))
            {
                Console.WriteLine("[{0:s}] {1:s} : {2:s} ", item.SearchStrategy.ToString(), item.ModuleName, item.Filepath);
            }

        }

        public void CleanPrint()
        {
            foreach (var item in this.Values.OrderBy(module => module.SearchStrategy))
            {
                item.CleanPrint();
            }
        }
    }

    class PeDependencies : IPrintable
    {
        public PeDependencies(PE Application, int recursion_depth, bool found_or_not, List<String> custom_searchfolders, List<ModuleSearchStrategy> ignore_search_strategies)
        {
            string RootFilename = Path.GetFileName(Application.Filepath);

            RootPe = Application;
            SxsEntriesCache = SxsManifest.GetSxsEntries(RootPe);
            ModulesCache = new ModuleEntries();
            MaxRecursion = recursion_depth;
            PrintFoundOrNot = found_or_not;
            CustomSearchFolders = custom_searchfolders;
            IgnoreSearchStrategies = ignore_search_strategies;

            Root = GetModuleItem(RootFilename, Application.Filepath, ModuleSearchStrategy.ROOT, 0);
            Root.LoadPe();
            Root.ResolveDependencies();
        }

        public Tuple<ModuleSearchStrategy, PE> ResolveModule(string ModuleName, List<String> custom_searchfolders, List<ModuleSearchStrategy> ignore_search_strategies)
        {
            return BinaryCache.ResolveModule(
                RootPe,
                ModuleName, /*DllImport.Name*/
                custom_searchfolders,
                ignore_search_strategies
            );
        }

        public bool isModuleCached(string ModuleName, string ModuleFilepath)
        {
            // Do not process twice the same item
            ModuleCacheKey ModuleKey = new ModuleCacheKey(ModuleName, ModuleFilepath);
            return ModulesCache.ContainsKey(ModuleKey);
        }

        public PeDependencyItem GetModuleItem(string ModuleName, string ModuleFilepath, ModuleSearchStrategy SearchStrategy, int RecursionLevel)
        {
            // Do not process twice the same item
            ModuleCacheKey ModuleKey = new ModuleCacheKey(ModuleName, ModuleFilepath);
            if (!ModulesCache.ContainsKey(ModuleKey))
            {
                ModulesCache[ModuleKey] = new PeDependencyItem(this, ModuleName, ModuleFilepath, SearchStrategy, RecursionLevel);
            }

            return ModulesCache[ModuleKey];
        }

        public void PrettyPrint()
        {
            ModulesVisited = new Dictionary<ModuleCacheKey, bool>();
            Root.PrettyPrint();
        }
        public void CleanPrint()
        {
            ModulesVisited = new Dictionary<ModuleCacheKey, bool>();
            Root.CleanPrint();
        }

        public bool VisitModule(string ModuleName, string ModuleFilepath)
        {
            ModuleCacheKey ModuleKey = new ModuleCacheKey(ModuleName, ModuleFilepath);

            // do not visit recursively the same node (in order to prevent stack overflow)
            if (ModulesVisited.ContainsKey(ModuleKey))
            {
                return false;
            }

            ModulesVisited[ModuleKey] = true;
            return true;
        }

        public ModuleEntries GetModules
        {
            get { return ModulesCache; }
        }

        public PeDependencyItem Root;
        public int MaxRecursion;
        public bool PrintFoundOrNot;
        public List<String> CustomSearchFolders;
        public List<ModuleSearchStrategy> IgnoreSearchStrategies;

        private PE RootPe;
        private SxsEntries SxsEntriesCache;
        private ModuleEntries ModulesCache;
        private Dictionary<ModuleCacheKey, bool> ModulesVisited;
    }

    class Program
    {
        public enum PrinterTypes
        {
            Pretty,
            Clean,
            Json,
        }

        public static void PrettyPrinter(IPrintable obj)
        {
            obj.PrettyPrint();
        }

        public static void CleanPrinter(IPrintable obj)
        {
            obj.CleanPrint();
        }

        public static void JsonPrinter(IPrintable obj)
        {
            JsonSerializerSettings Settings = new JsonSerializerSettings
            {
                // ReferenceLoopHandling = ReferenceLoopHandling.Serialize
            };

            Console.WriteLine(JsonConvert.SerializeObject(obj, Formatting.Indented, Settings));
        }

        public static void DumpKnownDlls(Action<IPrintable> Printer)
        {
            NtKnownDlls KnownDlls = new NtKnownDlls();
            Printer(KnownDlls);
        }

        public static void DumpApiSets(Action<IPrintable> Printer)
        {
            NtApiSet ApiSet = new NtApiSet();
            Printer(ApiSet);
        }

        public static void DumpApiSets(PE Application, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            NtApiSet ApiSet = new NtApiSet(Application);
            Printer(ApiSet);
        }

        public static void DumpManifest(PE Application, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            PEManifest Manifest = new PEManifest(Application);
            Printer(Manifest);
        }

        public static void DumpSxsEntries(PE Application, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            SxsDependencies SxsDeps = new SxsDependencies(Application);
            Printer(SxsDeps);
        }


        public static void DumpExports(PE Pe, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            PEExports Exports = new PEExports(Pe);
            Printer(Exports);
        }

        public static void DumpImports(PE Pe, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            PEImports Imports = new PEImports(Pe);
            Printer(Imports);
        }

        public static void DumpDependencyChain(PE Pe, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            if (Printer == JsonPrinter)
            {
                Console.Error.WriteLine("Json output is not currently supported when dumping the dependency chain.");
                return;
            }

            if (custom_searchfolders == null)
            {
                custom_searchfolders = new List<string>();
            }
            if (ignore_search_strategies == null)
            {
                ignore_search_strategies = new List<ModuleSearchStrategy>();
            }
            PeDependencies Deps = new PeDependencies(Pe, recursion_depth, found_or_not, custom_searchfolders, ignore_search_strategies);
            Printer(Deps);
        }

        public static void DumpModules(PE Pe, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true)
        {
            if (Printer == JsonPrinter)
            {
                Console.Error.WriteLine("Json output is not currently supported when dumping the dependency chain.");
                return;
            }

            if (custom_searchfolders == null)
            {
                custom_searchfolders = new List<string>();
            }
            if (ignore_search_strategies == null)
            {
                ignore_search_strategies = new List<ModuleSearchStrategy>();
            }
            PeDependencies Deps = new PeDependencies(Pe, recursion_depth, found_or_not, custom_searchfolders, ignore_search_strategies);
            Printer(Deps.GetModules);
        }

        public static void DumpUsage()
        {
            string Usage = String.Join(Environment.NewLine, //TODO maybe better to use the options values, currently they could get out of sync
                "Dependencies.exe : command line tool for dumping dependencies and various utilities.",
                "",
                "Usage : Dependencies.exe [OPTIONS] <FILE>",
                "",
                "Options :",
                "  -h -help : display this help",
                "  -printer : output results with given printer, types:", Environment.NewLine, Enum.GetNames(typeof(PrinterTypes)),
                "  -d -depth : limit recursion depth when analysing loaded modules or dependency chain. Default value is infinite (0)",
                "  -foundOrNot : for clean printer sets if found or not found dlls are printed when analysing loaded modules or dependency chain. Default value is found (true)",
                "  -customFolders : ;-separated additional folders to search for dlls when analysing loaded modules or dependency chain",
                "  -ignore : ignore given search strategies when analysing loaded modules or dependency chain, types:", Environment.NewLine, Enum.GetNames(typeof(ModuleSearchStrategy)),
                "  -knowndll : dump all the system's known dlls (x86 and x64)",
                "  -apisets : dump the system's ApiSet schema (api set dll -> host dll)",
                "  -apisetsdll : dump the ApiSet schema from apisetschema <FILE> (api set dll -> host dll)",
                "  -manifest : dump <FILE> embedded manifest, if it exists.",
                "  -sxsentries : dump all of <FILE>'s sxs dependencies.",
                "  -imports : dump <FILE> imports",
                "  -exports : dump <FILE> exports",
                "  -chain : dump <FILE> whole dependency chain",
                "  -modules : dump <FILE> resolved modules"

            );

            Console.WriteLine(Usage);
        }

        static Action<IPrintable> GetObjectPrinter(PrinterTypes printerType)
        {
            if (printerType == PrinterTypes.Clean)
                return CleanPrinter;

            if (printerType == PrinterTypes.Json)
                return JsonPrinter;

            return PrettyPrinter;
        }


        public delegate void DumpCommand(PE Application, Action<IPrintable> Printer, List<String> custom_searchfolders = null, List<ModuleSearchStrategy> ignore_search_strategies = null, int recursion_depth = 0, bool found_or_not = true);

        static void Main(string[] args)
        {
            // always the first call to make
            Phlib.InitializePhLib();

            bool show_help = false;
            PrinterTypes printerType = PrinterTypes.Pretty;
            int recursion_depth = 0;
            bool found_or_not = true;
            List<String> custom_searchfolders = null;
            List<ModuleSearchStrategy> ignore_search_strategies = null;
            bool early_exit = false;
            DumpCommand command = null;

            OptionSet opts = new OptionSet() {
                            { "h|help",  "show this message and exit", v => show_help = v != null },
                            { "printer=",  "output results with given printer, types:" + Environment.NewLine + Enum.GetNames(typeof(PrinterTypes)), v => {
                                if (v == null || !Enum.TryParse(v, true, out printerType))
                                {
                                    printerType = PrinterTypes.Pretty;
                                }
                            } },
                            { "d|depth=",  "limit recursion depth when analysing loaded modules or dependency chain. Default value is infinite (0)", (int v) =>  recursion_depth = v },
                            { "foundOrNot=",  "for clean printer sets if found or not found dlls are printed when analysing loaded modules or dependency chain. Default value is found (true)", (bool v) =>  found_or_not = v },
                            { "customFolders=", ";-separated additional folders to search for dlls when analysing loaded modules or dependency chain", v => {
                                if (v != null)
                                {
                                    custom_searchfolders = v.Split(';').ToList();
                                }
                            } },
                            { "ignore=",  "ignore given search strategies when analysing loaded modules or dependency chain, types:" + Environment.NewLine + Enum.GetNames(typeof(ModuleSearchStrategy)), v => {
                                if (v != null)
                                {
                                    ignore_search_strategies = v.Split(';').Select(x => (ModuleSearchStrategy)Enum.Parse(typeof(ModuleSearchStrategy), x)).ToList();
                                }
                            } },
                            { "knowndll", "List all known dlls", v => { DumpKnownDlls(GetObjectPrinter(printerType));  early_exit = true; } },
                            { "apisets", "List apisets redirections", v => { DumpApiSets(GetObjectPrinter(printerType));  early_exit = true; } },
                            { "apisetsdll", "List apisets redirections from apisetschema <FILE>", v => command = DumpApiSets },
                            { "manifest", "show manifest information embedded in <FILE>", v => command = DumpManifest },
                            { "sxsentries", "dump all of <FILE>'s sxs dependencies", v => command = DumpSxsEntries },
                            { "imports", "dump <FILE> imports", v => command = DumpImports },
                            { "exports", "dump <FILE> exports", v => command = DumpExports },
                            { "chain", "dump <FILE> whole dependency chain", v => command = DumpDependencyChain },
                            { "modules", "dump <FILE> resolved modules", v => command = DumpModules },
                        };

            List<string> eps = opts.Parse(args); //TODO catch if the option for return= are missing

            if (early_exit)
                return;

            if ((show_help) || (args.Length == 0) || (command == null))
            {
                DumpUsage();
                return;
            }

            if (eps.Count == 0)
            {
                Console.Error.WriteLine("[x] Command {0:s} needs to have a PE <FILE> argument", command.Method.Name);
                Console.Error.WriteLine("");

                DumpUsage();
                return;
            }

            String FileName = eps[0];
            if (!NativeFile.Exists(FileName))
            {
                Console.Error.WriteLine("[x] Could not find file {0:s} on disk", FileName);
                return;
            }

            Debug.WriteLine("[-] Loading file {0:s} ", FileName);
            PE Pe = new PE(FileName);
            if (!Pe.Load())
            {
                Console.Error.WriteLine("[x] Could not load file {0:s} as a PE", FileName);
                return;
            }

            command(Pe, GetObjectPrinter(printerType), custom_searchfolders, ignore_search_strategies, recursion_depth, found_or_not);

        }
    }
}
