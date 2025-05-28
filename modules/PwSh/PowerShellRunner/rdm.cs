using System;
using System.Reflection;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Management.Automation;
using System.Globalization;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;

namespace rdm
{
    public class rdm
    {
        private Runspace _runspace;
        private CustomPSHost _host;

        public rdm()
        {
            _host = new CustomPSHost();

            var state = InitialSessionState.CreateDefault();
            state.AuthorizationManager = null; // Bypass PowerShell execution policy

            _runspace = RunspaceFactory.CreateRunspace(_host, state);
            _runspace.Open();

            disEtw();
        }

        public string Invoke(string command)
        {
            if (_runspace == null || _runspace.RunspaceStateInfo.State != RunspaceState.Opened)
            {
                throw new InvalidOperationException("Runspace is not open.");
            }

            ((CustomPSHostUserInterface)_host.UI).ClearOutput();

            // Console.WriteLine("Executing PowerShell command: " + command);

            try
            {
                using (Pipeline pipeline = _runspace.CreatePipeline())
                {
                    pipeline.Commands.AddScript(command);
                    pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                    pipeline.Commands.Add("Out-Default");

                    pipeline.Invoke();
                }
            }
            catch (Exception ex)
            {
                ((CustomPSHostUserInterface)_host.UI).WriteErrorLine("PowerShell Error: " + ex.Message);
            }

            return ((CustomPSHostUserInterface)_host.UI).Output;
        }

        public void Dispose()
        {
            _runspace?.Dispose();
        }

        private void disEtw()
        {
            // Load System.Management.Automation assembly (PowerShell SDK)
            var psAssembly = typeof(System.Management.Automation.PSObject).Assembly;

            // Get the internal PSEtwLogProvider type
            Type etwLogProviderType = psAssembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
            if (etwLogProviderType == null)
                return;

            // Get the private static field 'etwProvider'
            FieldInfo etwProviderField = etwLogProviderType.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
            object etwProviderInstance = etwProviderField.GetValue(null);

            // Get System.Diagnostics.Eventing.EventProvider type (in System.Core)
            Type eventProviderType = typeof(System.Linq.Enumerable).Assembly.GetType("System.Diagnostics.Eventing.EventProvider");
            if (eventProviderType == null)
                return;

            // Get the private instance field 'm_enabled'
            FieldInfo mEnabledField = eventProviderType.GetField("m_enabled", BindingFlags.NonPublic | BindingFlags.Instance);

            // Set the 'm_enabled' field to 0 (disable ETW logging)
            mEnabledField.SetValue(etwProviderInstance, 0);
        }

        class CustomPSHost : PSHost
        {
            private Guid _hostId = Guid.NewGuid();
            private CustomPSHostUserInterface _ui = new CustomPSHostUserInterface();

            public override Guid InstanceId
            {
                get { return _hostId; }
            }

            public override string Name
            {
                get { return "ConsoleHost"; }
            }

            public override Version Version
            {
                get { return new Version(1, 0); }
            }

            public override PSHostUserInterface UI
            {
                get { return _ui; }
            }


            public override CultureInfo CurrentCulture
            {
                get { return Thread.CurrentThread.CurrentCulture; }
            }

            public override CultureInfo CurrentUICulture
            {
                get { return Thread.CurrentThread.CurrentUICulture; }
            }

            public override void EnterNestedPrompt()
            {
                throw new NotImplementedException("EnterNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void ExitNestedPrompt()
            {
                throw new NotImplementedException("ExitNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void NotifyBeginApplication()
            {
                return;
            }

            public override void NotifyEndApplication()
            {
                return;
            }

            public override void SetShouldExit(int exitCode)
            {
                return;
            }
        }

        class CustomPSHostUserInterface : PSHostUserInterface
        {
            // Replace StringBuilder with whatever your preferred output method is (e.g. a socket or a named pipe)
            private StringBuilder _sb;
            private CustomPSRHostRawUserInterface _rawUi = new CustomPSRHostRawUserInterface();

            public CustomPSHostUserInterface()
            {
                _sb = new StringBuilder();
            }

            public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _sb.Append(value);
            }

            public override void WriteLine()
            {
                _sb.Append("\n");
            }

            public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _sb.Append(value + "\n");
            }

            public override void Write(string value)
            {
                _sb.Append(value);
            }

            public override void WriteDebugLine(string message)
            {
                _sb.AppendLine("DEBUG: " + message);
            }

            public override void WriteErrorLine(string value)
            {
                _sb.AppendLine("ERROR: " + value);
            }

            public override void WriteLine(string value)
            {
                _sb.AppendLine(value);
            }

            public override void WriteVerboseLine(string message)
            {
                _sb.AppendLine("VERBOSE: " + message);
            }

            public override void WriteWarningLine(string message)
            {
                _sb.AppendLine("WARNING: " + message);
            }

            public override void WriteProgress(long sourceId, ProgressRecord record)
            {
                return;
            }

            public string Output
            {
                get { return _sb.ToString(); }
            }

            public void ClearOutput()
            {
                _sb.Clear();
            }

            public override Dictionary<string, PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
            {
                throw new NotImplementedException("Prompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
            {
                throw new NotImplementedException("PromptForChoice is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
            {
                throw new NotImplementedException("PromptForCredential1 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
            {
                throw new NotImplementedException("PromptForCredential2 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override PSHostRawUserInterface RawUI
            {
                get { return _rawUi; }
            }

            public override string ReadLine()
            {
                throw new NotImplementedException("ReadLine is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override System.Security.SecureString ReadLineAsSecureString()
            {
                throw new NotImplementedException("ReadLineAsSecureString is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }
        }


        class CustomPSRHostRawUserInterface : PSHostRawUserInterface
        {
            // Warning: Setting _outputWindowSize too high will cause OutOfMemory execeptions.  I assume this will happen with other properties as well
            private Size _windowSize = new Size { Width = 120, Height = 100 };

            private Coordinates _cursorPosition = new Coordinates { X = 0, Y = 0 };

            private int _cursorSize = 1;
            private ConsoleColor _foregroundColor = ConsoleColor.White;
            private ConsoleColor _backgroundColor = ConsoleColor.Black;

            private Size _maxPhysicalWindowSize = new Size
            {
                Width = int.MaxValue,
                Height = int.MaxValue
            };

            private Size _maxWindowSize = new Size { Width = 100, Height = 100 };
            private Size _bufferSize = new Size { Width = 100, Height = 1000 };
            private Coordinates _windowPosition = new Coordinates { X = 0, Y = 0 };
            private String _windowTitle = "";

            public override ConsoleColor BackgroundColor
            {
                get { return _backgroundColor; }
                set { _backgroundColor = value; }
            }

            public override Size BufferSize
            {
                get { return _bufferSize; }
                set { _bufferSize = value; }
            }

            public override Coordinates CursorPosition
            {
                get { return _cursorPosition; }
                set { _cursorPosition = value; }
            }

            public override int CursorSize
            {
                get { return _cursorSize; }
                set { _cursorSize = value; }
            }

            public override void FlushInputBuffer()
            {
                throw new NotImplementedException("FlushInputBuffer is not implemented.");
            }

            public override ConsoleColor ForegroundColor
            {
                get { return _foregroundColor; }
                set { _foregroundColor = value; }
            }

            public override BufferCell[,] GetBufferContents(Rectangle rectangle)
            {
                throw new NotImplementedException("GetBufferContents is not implemented.");
            }

            public override bool KeyAvailable
            {
                get { throw new NotImplementedException("KeyAvailable is not implemented."); }
            }

            public override Size MaxPhysicalWindowSize
            {
                get { return _maxPhysicalWindowSize; }
            }

            public override Size MaxWindowSize
            {
                get { return _maxWindowSize; }
            }

            public override KeyInfo ReadKey(ReadKeyOptions options)
            {
                throw new NotImplementedException("ReadKey is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
            }

            public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill)
            {
                throw new NotImplementedException("ScrollBufferContents is not implemented");
            }

            public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
            {
                throw new NotImplementedException("SetBufferContents is not implemented.");
            }

            public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
            {
                throw new NotImplementedException("SetBufferContents is not implemented");
            }

            public override Coordinates WindowPosition
            {
                get { return _windowPosition; }
                set { _windowPosition = value; }
            }

            public override Size WindowSize
            {
                get { return _windowSize; }
                set { _windowSize = value; }
            }

            public override string WindowTitle
            {
                get { return _windowTitle; }
                set { _windowTitle = value; }
            }
        }

    }
}
