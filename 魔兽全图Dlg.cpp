
// 魔兽全图Dlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "魔兽全图.h"
#include "魔兽全图Dlg.h"
#include "afxdialogex.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// C魔兽全图Dlg 对话框



C魔兽全图Dlg::C魔兽全图Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MY_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void C魔兽全图Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(C魔兽全图Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &C魔兽全图Dlg::OnBnClickedOk)
END_MESSAGE_MAP()


// C魔兽全图Dlg 消息处理程序

BOOL C魔兽全图Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void C魔兽全图Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void C魔兽全图Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR C魔兽全图Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

#define PATCH(i, w) \
WriteProcessMemory(hopen, (LPVOID)(g_dwGameAddr + i), w, sizeof(w) - 1, 0);

DWORD C魔兽全图Dlg::GetDLLBase(WCHAR* DllName, DWORD tPid)
 {
	
 HANDLE snapMod;
	MODULEENTRY32 me32;
	WCHAR LastDLLPath[260];
	 if (tPid == 0) return 0;
	 snapMod =CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,tPid);
	 me32.dwSize = sizeof(MODULEENTRY32);
	 if (Module32First(snapMod, &me32))
	 {
		 do
		 {
			 if (memcmp(DllName, (const char*)me32.szModule,wcslen(DllName)) == 0)
			 {
				 memcpy(LastDLLPath, me32.szExePath,sizeof(me32.szExePath)); //game.dll 路径
				 CloseHandle(snapMod);
				 return (DWORD)me32.modBaseAddr;
			 }
		 } while (Module32Next(snapMod, &me32));
	 }
	 else {
	 }
	 CloseHandle(snapMod);

	 return 0;
}


typedef enum WC3VER {
	_UN, _120E, _124B, _124E, _125B, _126B
};
WC3VER g_War3Ver;
void C魔兽全图Dlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	//Find wc3 windows Warcraft III
	HWND hwar3 = ::FindWindow(NULL, _T("Warcraft III"));
	if (hwar3==NULL)
	{
		MessageBox(_T("魔兽未启动"));
		return;
	}
	DWORD PID, TID;
	TID = ::GetWindowThreadProcessId(hwar3, &PID);
	//提升打开魔兽争霸的权限
	TOKEN_PRIVILEGES tkp;
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bool ret=AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	if (!ret){
		MessageBox(_T("提权失败!"));
		return;
	}

	HANDLE hopen = ::OpenProcess(PROCESS_ALL_ACCESS,FALSE, PID);

	if (!hopen)
	{
		MessageBox(_T("进程打开失败!"));
		return;
	}
	//DWORD GameAddr = GetGameDLLAddr(hopen, _T("Game.dll"));
	DWORD g_dwGameAddr=GetDLLBase(_T("Game.dll"), PID);
	switch (_124E)
	{
	case _120E: {
		//1.20E     
///大地图去除迷雾     
		PATCH(0x406B53, "/x90/x8B/x09");
		///大地图显示单位     
		PATCH(0x2A0930, "/xD2");
		///大地图显示隐形     
		PATCH(0x17D4C2, "/x90/x90");
		PATCH(0x17D4CC, "/xEB/x00/xEB/x00/x75/x30");
		///分辨幻影     
		PATCH(0x1ACFFC, "/x40/xC3");
		///显示神符     
		PATCH(0x2A07C5, "/x49/x4B/x33/xDB/x33/xC9");
		///小地图去除迷雾     
		PATCH(0x147C53, "/xEC");
		//显示单位     
		PATCH(0x1491A8, "/x00");
		// 显示隐形
		PATCH(0x1494E0, "/x33/xC0/x0F/x85");
		//敌方信号
		PATCH(0x321CC4, "/x39/xC0/x0F/x85");
		PATCH(0x321CD7, "/x39/xC0/x75");
		//他人提示     
		PATCH(0x124DDD, "/x39/xC0/x0F/x85");
		// 显示敌方头像
		PATCH(0x137BA5, "/xE7/x7D");
		PATCH(0x137BAC, "/x85/xA3/x02/x00/x00/xEB/xCE/x90/x90/x90/x90");
		//盟友头像     
		PATCH(0x137BA5, "/xE7/x7D");
		PATCH(0x137BB1, "/xEB/xCE/x90/x90/x90/x90");
		//数字显攻速     
		PATCH(0x802E67, "/x32");
		PATCH(0x13BA61, "/x90/xD9/x45/x08/x83/xEC/x08/xDD/x1C/x24/x68");
		//资源面板     
		PATCH(0x13EF03, "/xEB");
		// 允许交易
		PATCH(0x127B3D, "/x40/xB8/x64");
		//显示技能     
		PATCH(0x12DC1A, "/x33/xC0");
		PATCH(0x12DC5A, "/x33/xC0");
		PATCH(0x1BFABE, "/xEB");
		PATCH(0x442CC0, "/x90/x40/x30/xC0/x90/x90");
		PATCH(0x443375, "/x30/xC0");
		PATCH(0x45A641, "/x90/x90/x33/xC0/x90/x90");
		PATCH(0x45E79E, "/x90/x90");
		PATCH(0x45E7A0, "/x33/xC0/x90/x90");
		PATCH(0x466527, "/x90/x90");
		PATCH(0x46B258, "/x90/x33/xC0/x90/x90/x90");
		PATCH(0x4A11A0, "/x33/xC0");
		PATCH(0x54C0BF, "/x90/x33/xC0/x90/x90/x90");
		PATCH(0x5573FE, "/x90/x90/x90/x90/x90/x90");
		PATCH(0x55E15C, "/x90/x90");
		///资源条     
		PATCH(0x150981, "/xEB/x02");
		PATCH(0x1509FE, "/xEB/x02");
		PATCH(0x151597, "/xEB/x02");
		PATCH(0x151647, "/xEB/x02");
		PATCH(0x151748, "/xEB/x02");
		PATCH(0x1BED19, "/xEB/x02");
		PATCH(0x314A9E, "/xEB/x02");
		PATCH(0x21EAD4, "/xEB");
		PATCH(0x21EAE8, "/x03");
		// 野外显血
		PATCH(0x166E5E, "/x90/x90/x90/x90/x90/x90/x90/x90");
		PATCH(0x16FE0A, "/x33/xC0/x90/x90");
		//视野外点选
		PATCH(0x1BD5A7, "/x90/x90");
		PATCH(0x1BD5BB, "/xEB");
		// 无限取消
		PATCH(0x23D60F, "/xEB");
		PATCH(0x21EAD4, "/x03");
		PATCH(0x21EAE8, "/x03");
		//过-MH(蓝宝石)     
		PATCH(0x2C5A7E, "/x90/x90");
		// 反 - AH
		PATCH(0x2C240C, "/x3C/x4C/x74/x04/xB0/xFF/xEB/x04/xB0/xB0/x90/x90");
		PATCH(0x2D34ED, "/xE9/xB3/x00/x00/x00/x90");
	}
			break;
	case _124B:
			//小地图显示单位
				PATCH(0x361EAB, "\x90\x90\x39\x5E\x10\x90\x90\xB8\x00\x00\x00\x00\xEB\x07");
		break;
	case _124E: {
		// 1.24E  
		//大地图去除迷雾
		char w[] = { 0x15,0x70 };
		ret=WriteProcessMemory(hopen, (LPVOID)(g_dwGameAddr + 0x74D1BA), w, 2, 0);
		if (!ret)
		{
			DWORD err = GetLastError();
			return;
		}
		//PATCH(0x74D1B9, "/xB2/x00/x90/x90/x90/x90");
		
		//大地图显示单位
	/*		PATCH(0x39EBBC, "/x75");
		PATCH(0x3A2030, "/x90/x90");
		PATCH(0x3A20DB, "/x90/x90");*/
		//显示隐形单位
		//PATCH(0x362391, "/x3B");
		//PATCH(0x362394, "/x85");
		//PATCH(0x39A51B, "/x90/x90/x90/x90/x90/x90");
		//PATCH(0x39A52E, "/x90/x90/x90/x90/x90/x90/x90/x90/x33/xC0/x40");
		////分辨幻影   
		//PATCH(0x28357C, "/x40/xC3");
		//// 显示物品
		//	PATCH(0x3A201B, "/xEB");
		//PATCH(0x40A864, "/x90/x90");
		////小地图 去除迷雾
		//	PATCH(0x357065, "/x90/x90");
		////小地图显示单位
		//	PATCH(0x361F7C, "/x00");
		// 小地图显示隐形
			// 敌方信号
		//	PATCH(0x43F9A6, "/x3B");
		//PATCH(0x43F9A9, "/x85");
		//PATCH(0x43F9B9, "/x3B");
		//PATCH(0x43F9BC, "/x85");
		//// 他人提示
		//	PATCH(0x3345E9, "/x39/xC0/x0F/x85");
		////敌方头像
		//	PATCH(0x371700, "/xE8/x3B/x28/x03/x00/x85/xC0/x0F/x85/x8F/x02/x00/x00/xEB/xC9/x90/x90/x90/x90");
		//// 盟友头像
		//	PATCH(0x371700, "/xE8/x3B/x28/x03/x00/x85/xC0/x0F/x84/x8F/x02/x00/x00/xEB/xC9/x90/x90/x90/x90");
		////数显攻速
		//	PATCH(0x87EA63, "/x25/x30/x2E/x32/x66/x7C/x52/x00");
		//PATCH(0x87EA70, "/x8D/x4C/x24/x18/xD9/x44/x24/x60/x83/xEC/x08/xDD/x1C/x24/x68");
		//
		////资源面板     
		//PATCH(0x36058A, "/x90");
		//PATCH(0x36058B, "/x90");
		/////   允许交易  
		//PATCH(0x34E8E2, "/xB8/xC8/x00/x00");
		//PATCH(0x34E8E7, "/x90");
		//PATCH(0x34E8EA, "/xB8/x64/x00/x00");
		//PATCH(0x34E8EF, "/x90");
		////显示技能
		//	PATCH(0x2031EC, "/x90/x90/x90/x90/x90/x90");
		//PATCH(0x34FDE8, "/x90/x90");
		//// 技能CD
		//	PATCH(0x28ECFE, "/xEB");
		//PATCH(0x34FE26, "/x90/x90/x90/x90");
		////资源条     
		////野外显血     
		/////视野外点击  
		//PATCH(0x285CBC, "/x90/x90");
		//PATCH(0x285CD2, "/xEB");
		////无限取消     
		//PATCH(0x57BA7C, "/xEB");
		//PATCH(0x5B2D77, "/x03");
		//PATCH(0x5B2D8B, "/x03");
		//// 过 - MH
		//	PATCH(0x3C84C7, "/xEB/x11");
		//PATCH(0x3C84E7, "/xEB/x11");
		////反 - AH
		//	PATCH(0x3C6EDC, "/xB8/xFF/x00/x00/x00/xEB");
		//PATCH(0x3CC3B2, "/xEB");
	//至于作弊代码你们是直接写， 还是写成一个方法调用， 随你们自己。
		break;
	}
	case _UN: {
		break;
	}
	default:
			break;
	}
	CloseHandle(hopen);
}

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetList,
	MemorySectionName,
	MemoryBasicVlmInformation
} MEMORY_INFORMATION_CLASS;

typedef long (NTAPI* PF_ZwQueryVirtualMemory)
(IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN ULONG MemoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
DWORD  C魔兽全图Dlg::GetGameDLLAddr(HANDLE hWar3Handle, WCHAR* ModuleName)
{
	DWORD startAddr;
	BYTE buffer[MAX_PATH * 2 + 4];
	MEMORY_BASIC_INFORMATION memBI;
	PUNICODE_STRING secName;
	PF_ZwQueryVirtualMemory ZwQueryVirtualMemory;

	startAddr = 0x00000000;
	ZwQueryVirtualMemory = (PF_ZwQueryVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryVirtualMemory");
	do {
		if (ZwQueryVirtualMemory(hWar3Handle, (PVOID)startAddr, MemoryBasicInformation, &memBI, sizeof(memBI), 0) >= 0 &&
			(memBI.Type == MEM_IMAGE))
		{
			if (ZwQueryVirtualMemory(hWar3Handle, (PVOID)startAddr, MemorySectionName, buffer, sizeof(buffer), 0) >= 0)
			{
				secName = (PUNICODE_STRING)buffer;
				if (_wcsicmp(ModuleName, wcsrchr(secName->Buffer, '\\') + 1) == 0)
				{
					return startAddr;
				}
			}
			// 递增基址,开始下一轮查询! 
		}
		startAddr += 0x10000;
	} while (startAddr < 0xF0000000);
	return 0;
};