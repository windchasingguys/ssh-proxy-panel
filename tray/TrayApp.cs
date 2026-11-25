// SSH 隧道面板 —— Windows 托盘壳
// 作用：常驻托盘，负责拉起/守护 ssh-proxy.exe（真正的控制器），菜单里能开面板、批量开关、退出。
// 编译：scripts/build-exe.mjs 里用 csc /target:winexe 编成 ssh-proxy-tray.exe（无控制台窗口）。
using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace SshProxyTray
{
    internal static class Program
    {
        private static Mutex _mutex;

        [STAThread]
        private static void Main(string[] args)
        {
            // --prepare：只解包并自检（给安装脚本/CI 用），不弹托盘
            if (args != null && Array.IndexOf(args, "--prepare") >= 0)
            {
                try
                {
                    var ctx = new TrayContext(false);
                    Console.WriteLine("core: " + ctx.CorePath);
                    Console.WriteLine("web : " + Path.Combine(ctx.RuntimeDir, "public"));
                    ctx.VerifyExtracted();
                    Console.WriteLine("ok");
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("prepare failed: " + ex.Message);
                    Environment.Exit(1);
                }
                return;
            }

            bool createdNew;
            _mutex = new Mutex(true, "Local\\SshProxyTray", out createdNew);
            if (!createdNew)
            {
                return; // 托盘里已经有一个了
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new TrayContext(true));
        }
    }

    internal sealed class TrayContext : ApplicationContext
    {
        private const int DefaultPort = 7788;
        private const string CoreName = "ssh-proxy-core.exe";

        // 内嵌的前端文件（资源名 web.<文件名>）
        private static readonly string[] WebFiles = new string[] { "index.html", "app.js", "style.css" };

        private readonly string _appDir;
        private readonly string _configPath;
        private readonly string _logPath;
        private readonly string _runtimeDir;
        private readonly string _corePath;
        private readonly NotifyIcon _icon;
        private readonly ToolStripMenuItem _statusItem;
        private readonly System.Windows.Forms.Timer _watch;
        private Process _daemon;
        private bool _stopping;

        public string CorePath { get { return _corePath; } }
        public string RuntimeDir { get { return _runtimeDir; } }

        /// <summary>--prepare 的自检：解出来的文件必须真的在</summary>
        public void VerifyExtracted()
        {
            if (!File.Exists(_corePath))
            {
                throw new InvalidOperationException("控制器没有解包出来: " + _corePath);
            }
            foreach (string name in WebFiles)
            {
                string file = Path.Combine(_runtimeDir, "public", name);
                if (!File.Exists(file))
                {
                    throw new InvalidOperationException("前端文件没有解包出来: " + file);
                }
            }
        }

        public TrayContext() : this(true) { }

        public TrayContext(bool withUi)
        {
            _appDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            _runtimeDir = PrepareRuntime();
            _corePath = Path.Combine(_runtimeDir, CoreName);
            _configPath = ResolveConfigPath();
            _logPath = Path.Combine(_appDir, "tray-daemon.log");

            if (!withUi)
            {
                return; // --prepare 只要解包结果
            }

            var menu = new ContextMenuStrip();
            _statusItem = new ToolStripMenuItem("状态：启动中…") { Enabled = false };
            menu.Items.Add(_statusItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("打开面板", null, OnOpenPanel).Font = new Font(menu.Font, FontStyle.Bold);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("全部开启", null, delegate { CallApi("/api/all/start", "已下发全部开启"); });
            menu.Items.Add("全部关闭", null, delegate { CallApi("/api/all/stop", "已下发全部关闭"); });
            menu.Items.Add("重载配置", null, delegate { CallApi("/api/reload", "配置已重载"); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("打开配置文件夹", null, OnOpenFolder);
            menu.Items.Add("编辑 tunnels.json", null, delegate { OpenPath(_configPath); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出", null, OnExit);

            _icon = new NotifyIcon();
            _icon.Icon = BuildIcon();
            _icon.Text = "SSH 隧道面板";
            _icon.ContextMenuStrip = menu;
            _icon.Visible = true;
            _icon.DoubleClick += OnOpenPanel;

            EnsureConfig();
            StartDaemon();

            _watch = new System.Windows.Forms.Timer();
            _watch.Interval = 3000;
            _watch.Tick += OnWatch;
            _watch.Start();

            _icon.ShowBalloonTip(2000, "SSH 隧道面板", "已在后台运行。双击托盘图标打开面板。", ToolTipIcon.Info);
        }

        /* ---------------- 单文件：把内嵌的控制器/前端解包出来 ---------------- */

        private string PrepareRuntime()
        {
            string baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ssh-proxy",
                "runtime");
            string dir = Path.Combine(baseDir, BuildInfo.BuildId);
            Directory.CreateDirectory(dir);

            string corePath = Path.Combine(dir, CoreName);
            if (!File.Exists(corePath) || new FileInfo(corePath).Length == 0)
            {
                Extract("core", corePath);
            }

            string webDir = Path.Combine(dir, "public");
            Directory.CreateDirectory(webDir);
            foreach (string name in WebFiles)
            {
                Extract("web." + name, Path.Combine(webDir, name));
            }

            // 清掉旧版本解包出来的目录（尽力而为）
            try
            {
                foreach (string old in Directory.GetDirectories(baseDir))
                {
                    if (string.Equals(old.TrimEnd('\\'), dir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    try
                    {
                        Directory.Delete(old, true);
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }

            return dir;
        }

        private static void Extract(string resourceName, string target)
        {
            System.Reflection.Assembly asm = System.Reflection.Assembly.GetExecutingAssembly();
            using (Stream input = asm.GetManifestResourceStream(resourceName))
            {
                if (input == null)
                {
                    throw new InvalidOperationException("缺少内嵌资源: " + resourceName);
                }
                string tmp = target + ".tmp";
                using (var output = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    input.CopyTo(output, 81920);
                }
                if (File.Exists(target))
                {
                    File.Delete(target);
                }
                File.Move(tmp, target);
            }
        }

        /// <summary>配置默认放在 exe 旁边（便携）；目录不可写就退回 %APPDATA%</summary>
        private string ResolveConfigPath()
        {
            try
            {
                string probe = Path.Combine(_appDir, ".write-probe");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return Path.Combine(_appDir, "tunnels.json");
            }
            catch
            {
                string alt = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ssh-proxy");
                Directory.CreateDirectory(alt);
                return Path.Combine(alt, "tunnels.json");
            }
        }

        /* ---------------- 守护进程 ---------------- */

        private void EnsureConfig()
        {
            if (File.Exists(_configPath))
            {
                return;
            }
            try
            {
                RunHidden("init --target \"" + _configPath + "\"", 15000);
            }
            catch
            {
                // 生成失败就让用户自己处理，面板起来后也能在界面里新建
            }
        }

        private void StartDaemon()
        {
            if (_daemon != null && !_daemon.HasExited)
            {
                return;
            }
            if (!File.Exists(_corePath))
            {
                SetStatus("状态：找不到 ssh-proxy.exe");
                return;
            }
            try
            {
                var psi = new ProcessStartInfo();
                psi.FileName = _corePath;
                psi.Arguments = "serve --config \"" + _configPath + "\" --quiet";
                psi.WorkingDirectory = _appDir;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.StandardOutputEncoding = Encoding.UTF8;
                psi.StandardErrorEncoding = Encoding.UTF8;
                psi.EnvironmentVariables["SSH_PROXY_TRAY"] = "1";

                _daemon = new Process();
                _daemon.StartInfo = psi;
                _daemon.EnableRaisingEvents = true;
                _daemon.OutputDataReceived += delegate(object s, DataReceivedEventArgs e) { AppendLog(e.Data); };
                _daemon.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) { AppendLog(e.Data); };
                _daemon.Exited += delegate { SetStatus("状态：已停止"); };
                _daemon.Start();
                _daemon.BeginOutputReadLine();
                _daemon.BeginErrorReadLine();
                SetStatus("状态：运行中 · " + BaseUrl());
            }
            catch (Exception ex)
            {
                SetStatus("状态：启动失败");
                ShowBalloon("启动失败：" + ex.Message, ToolTipIcon.Error);
            }
        }

        private void OnWatch(object sender, EventArgs e)
        {
            if (_stopping)
            {
                return;
            }
            if (_daemon == null || _daemon.HasExited)
            {
                SetStatus("状态：已停止，正在重启…");
                StartDaemon();
            }
        }

        /* ---------------- 菜单动作 ---------------- */

        private void OnOpenPanel(object sender, EventArgs e)
        {
            StartDaemon();
            OpenPath(BaseUrl());
        }

        private void OnOpenFolder(object sender, EventArgs e)
        {
            OpenPath(_appDir);
        }

        private void OnExit(object sender, EventArgs e)
        {
            _stopping = true;
            _watch.Stop();
            try
            {
                PostJson("/api/shutdown", null, 1500);
            }
            catch
            {
            }
            try
            {
                if (_daemon != null && !_daemon.HasExited)
                {
                    if (!_daemon.WaitForExit(3000))
                    {
                        _daemon.Kill();
                    }
                }
            }
            catch
            {
            }

            _icon.Visible = false;
            _icon.Dispose();
            ExitThread();
        }

        private void CallApi(string path, string okMessage)
        {
            StartDaemon();
            try
            {
                PostJson(path, null, 4000);
                ShowBalloon(okMessage, ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                ShowBalloon("操作失败：" + ex.Message, ToolTipIcon.Error);
            }
        }

        /* ---------------- HTTP ---------------- */

        private string Token()
        {
            string fromEnv = Environment.GetEnvironmentVariable("SSH_PROXY_TOKEN");
            if (!string.IsNullOrEmpty(fromEnv))
            {
                return fromEnv;
            }
            try
            {
                if (!File.Exists(_configPath))
                {
                    return "";
                }
                string text = File.ReadAllText(_configPath);
                Match panel = Regex.Match(text, "\"panel\"\\s*:\\s*\\{", RegexOptions.Singleline);
                if (!panel.Success)
                {
                    return "";
                }
                Match m = Regex.Match(text.Substring(panel.Index), "\"token\"\\s*:\\s*\"([^\"]*)\"");
                return m.Success ? m.Groups[1].Value : "";
            }
            catch
            {
                return "";
            }
        }

        private int Port()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    string text = File.ReadAllText(_configPath);
                    Match panel = Regex.Match(text, "\"panel\"\\s*:\\s*\\{", RegexOptions.Singleline);
                    if (panel.Success)
                    {
                        Match m = Regex.Match(text.Substring(panel.Index), "\"port\"\\s*:\\s*(\\d+)");
                        if (m.Success)
                        {
                            return int.Parse(m.Groups[1].Value);
                        }
                    }
                }
            }
            catch
            {
            }
            return DefaultPort;
        }

        private string BaseUrl()
        {
            return "http://127.0.0.1:" + Port() + "/";
        }

        private void PostJson(string path, string body, int timeoutMs)
        {
            using (var client = new CookieAwareClient())
            {
                client.Headers["x-panel-token"] = Token();
                if (body != null)
                {
                    client.Headers["content-type"] = "application/json; charset=utf-8";
                }
                client.Timeout = timeoutMs;
                client.UploadString(new Uri(new Uri(BaseUrl()), path.TrimStart('/')), "POST", body ?? "{}");
            }
        }

        /* ---------------- 杂项 ---------------- */

        private void RunHidden(string arguments, int timeoutMs)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = _corePath;
            psi.Arguments = arguments;
            psi.WorkingDirectory = _appDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(timeoutMs);
            }
        }

        private void SetStatus(string text)
        {
            if (_icon != null)
            {
                // NotifyIcon.Text 最多 63 个字符
                string shortText = text.Length > 60 ? text.Substring(0, 60) : text;
                _icon.Text = shortText;
            }
            if (_statusItem != null)
            {
                _statusItem.Text = text;
            }
        }

        private void ShowBalloon(string message, ToolTipIcon icon)
        {
            try
            {
                _icon.ShowBalloonTip(3000, "SSH 隧道面板", message, icon);
            }
            catch
            {
            }
        }

        private void AppendLog(string line)
        {
            if (string.IsNullOrEmpty(line))
            {
                return;
            }
            try
            {
                File.AppendAllText(_logPath, DateTime.Now.ToString("HH:mm:ss") + " " + line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }

        private static void OpenPath(string target)
        {
            try
            {
                Process.Start(new ProcessStartInfo(target) { UseShellExecute = true });
            }
            catch
            {
            }
        }

        /// <summary>托盘图标：深色圆角底 + 绿色箭头（不依赖外部 ico 文件）</summary>
        private static Icon BuildIcon()
        {
            using (var bmp = new Bitmap(32, 32))
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                using (var bg = new GraphicsPath())
                {
                    int r = 8;
                    bg.AddArc(0, 0, r, r, 180, 90);
                    bg.AddArc(31 - r, 0, r, r, 270, 90);
                    bg.AddArc(31 - r, 31 - r, r, r, 0, 90);
                    bg.AddArc(0, 31 - r, r, r, 90, 90);
                    bg.CloseFigure();
                    using (var brush = new SolidBrush(Color.FromArgb(255, 17, 26, 36)))
                    {
                        g.FillPath(brush, bg);
                    }
                }
                using (var pen = new Pen(Color.FromArgb(255, 52, 211, 153), 2.6f))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    g.DrawLines(pen, new[]
                    {
                        new PointF(8, 22),
                        new PointF(16, 10),
                        new PointF(24, 22)
                    });
                }
                IntPtr handle = bmp.GetHicon();
                return Icon.FromHandle(handle);
            }
        }
    }

    /// <summary>WebClient 默认不保存 Cookie，也没有 Timeout；这里两个都补上（面板登录用的是 HttpOnly Cookie）</summary>
    internal sealed class CookieAwareClient : WebClient
    {
        private readonly CookieContainer _cookies = new CookieContainer();

        /// <summary>毫秒；&lt;=0 用 30 秒默认值</summary>
        public int Timeout { get; set; }

        protected override WebRequest GetWebRequest(Uri address)
        {
            WebRequest request = base.GetWebRequest(address);
            var http = request as HttpWebRequest;
            if (http != null)
            {
                http.CookieContainer = _cookies;
                http.Timeout = Timeout > 0 ? Timeout : 30000;
                http.ReadWriteTimeout = Timeout > 0 ? Timeout : 30000;
            }
            return request;
        }
    }
}
