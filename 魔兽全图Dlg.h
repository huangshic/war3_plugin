
// 魔兽全图Dlg.h: 头文件
//

#pragma once


// C魔兽全图Dlg 对话框
class C魔兽全图Dlg : public CDialogEx
{
// 构造
public:
	C魔兽全图Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MY_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg
		DWORD GetDLLBase(WCHAR* DllName, DWORD tPid);
	void OnBnClickedOk();
	DWORD GetGameDLLAddr(HANDLE hWar3Handle, WCHAR* ModuleName);
};
