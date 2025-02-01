DEF_SHELLCODE = "" 
DEF_COFF      = ""
DEF_PE        = ""
DEF_SLEEPMASK = ""
DEF_SLEEPTIME = ""
DEF_DBGMODE   = ""
DEF_APIEXEC   = ""

DEF_HOSTS     = ""
DEF_PORT      = ""
DEF_USERAGENT = ""

TASK_CODE_ERROR     = 0x100
TASK_CODE_CHECKIN   = 0x101
TASK_CODE_OUTPUT    = 0x102
TASK_CODE_GETJOB    = 0x103
TASK_CODE_NOJOB     = 0x104

TASK_SLEEP_TIME = 0x500
TASK_SLEEP_MASK = 0x501
TASK_PROCESS    = 0x502
TASK_CMD        = 0x503
TASK_PWSH       = 0x504
TASK_SOCKS      = 0x505
TASK_SELF_DEL   = 0x506
TASK_EXPLORER   = 0x507
TASK_UPLOAD     = 0x508
TASK_DOWNLOAD   = 0x509
TASK_EXIT_T     = 0x510
TASK_EXIT_P     = 0x511

TASK_SHELLCODE_T = 0x700
TASK_PE_T        = 0x701
TASK_COFF_T      = 0x702
TASK_EXEC_API    = 0x703

TASK_SUB_PROCESS_LIST   = 0x70
TASK_SUB_PROCESS_CREATE = 0x71
TASK_SUB_PROCESS_KILL   = 0x72
TASK_SUB_PROCESS_PPID   = 0x73
TASK_SUB_PROCESS_BLOCKS = 0x74

TASK_SUB_EXPLORER_LIST  = 0x70
TASK_SUB_EXPLORER_CAT   = 0x71
TASK_SUB_EXPLORER_PWD   = 0x72
TASK_SUB_EXPLORER_CD    = 0x73
TASK_SUB_EXPLORER_MV    = 0x74
TASK_SUB_EXPLORER_CP    = 0x75
TASK_SUB_EXPLORER_DEL   = 0x76
TASK_SUB_EXPLORER_MKDIR = 0x77

ExecApiMethods :list= {
    "WinAPI": 0x00,
    "NTAPI" : 0x01,
    "Indirect Syscall": 0x02
};

CoffTechniques :list= {
    "Classic" : 0x00,
    "Stomping": 0x01
};

ShellcodeTechniques :list=  {
    "Classic" : 0x01,
    "Stomping": 0x02
};

PeTechniques :list= {
    "Reflection"    : 0x00,
    "Overloading"   : 0x01,
    "Doppelganging" : 0x02
};

SleepMasks :list= {
    "WaitForSingleObject": 0x00,
    "Timer" : 0x01,
    "APC"   : 0x02
};

def GetFileBytes( AgentPath ) -> bytes:
    with open( AgentPath, 'rb' ) as File:
        return File.read()
