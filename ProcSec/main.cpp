#include "main.h"


int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nCmdShow)
{
	//GetProcessModuleInformation(19376);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	g_hInst = hInstance;

	WNDCLASSEXW wcex = { 0 };

	wcex.cbSize = sizeof(WNDCLASSEXW);
	wcex.lpfnWndProc = WndProc;
	wcex.hInstance = hInstance;
	wcex.lpszClassName = L"ProcSec";
	wcex.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDR_MENU1);
	wcex.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICON1));

	::RegisterClassExW(&wcex);

	HWND hWnd = CreateWindowW(L"ProcSec", L"Process Security", WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
	if (hWnd == NULL) {
		::MessageBoxW(nullptr, L"CreateWindowW Failed", nullptr, MB_ICONERROR | MB_OK);
		return EXIT_FAILURE;
	}

	::ShowWindow(hWnd, nCmdShow);

	MSG msg;

	// Message Queue
	while (GetMessage(&msg, nullptr, 0, 0)) {
		::TranslateMessage(&msg);
		::DispatchMessageW(&msg);
	}

	return TRUE;
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_CREATE:
		SetDebugPrivilege();
		::InitCommonControls();

		g_hList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
			WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
			CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, hWnd, (HMENU)IDC_MAIN_LIST, ((LPCREATESTRUCT)lParam)->hInstance, nullptr);

		ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT);

		AddColumns(g_hList);
		GetProcessList(g_hList);
		break;

	case WM_SIZE:
		::MoveWindow(g_hList, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
		break;

	case WM_NOTIFY: {
		LPNMHDR hdr = (LPNMHDR)lParam;

		if (hdr->code == NM_CUSTOMDRAW && hdr->idFrom == IDC_MAIN_LIST) {
			NMLVCUSTOMDRAW* plvcd = (NMLVCUSTOMDRAW*)hdr;

			if (plvcd->nmcd.dwDrawStage == CDDS_PREPAINT)
				return CDRF_NOTIFYITEMDRAW;

			else if (plvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
				SetColor(plvcd);

				return CDRF_NEWFONT;
			}
		}

		if (hdr->hwndFrom == g_hList && hdr->code == NM_RCLICK)
			ShowPopupMenu(hWnd);

		else if (hdr->hwndFrom == g_hList && hdr->code == NM_DBLCLK)
			::DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_PROPERTIES), hWnd, PropertiesDialog);

		else if (hdr->hwndFrom == g_hList && hdr->code == LVN_COLUMNCLICK) {
			NMLISTVIEW* pnmlv = (NMLISTVIEW*)lParam;
			HWND hHeader = ListView_GetHeader(g_hList);
			HDITEM hdi = { 0 };
			hdi.mask = HDI_FORMAT;
			
			if (g_SortColumn == pnmlv->iSubItem) {
				g_SortState++;
				if (g_SortState > 2)
					g_SortState = 0;
			}
			else {
				g_SortColumn = pnmlv->iSubItem;
				g_SortState = 1;
			}

			if (g_SortColumn >= 0 && g_SortColumn <= LV_PID) {

				Header_GetItem(hHeader, g_SortColumn, &hdi);
				hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);

				// Clean Previous Arrow
				if (g_PreviousSortColumn != -1) {
					Header_GetItem(hHeader, g_PreviousSortColumn, &hdi);
					hdi.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
					Header_SetItem(hHeader, g_PreviousSortColumn, &hdi);
				}

				if (g_SortState == 0)
					ListView_SortItems(g_hList, CompareOriginal, 0);

				else {
					ListView_SortItems(g_hList, CompareFunc, g_SortColumn);
					if (g_SortState == 1)
						hdi.fmt |= HDF_SORTUP;
					else if (g_SortState == 2)
						hdi.fmt |= HDF_SORTDOWN;
				}

				g_PreviousSortColumn = g_SortColumn;
				Header_SetItem(hHeader, g_SortColumn, &hdi);
			}
		}

		else if (hdr->hwndFrom == g_hList && hdr->code == LVM_DELETEITEM) {
			NMLISTVIEW* pnmlv = (NMLISTVIEW*)lParam;
			PPROC_ITEM data = (PPROC_ITEM)pnmlv->lParam;
			if (data)
				free(data);
		}

		break;
	}

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case PM_PROPERTIES:
			::DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_PROPERTIES), hWnd, PropertiesDialog);
			break;

		case PM_PEB_INFO:
			::DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_PEB), hWnd, PEBDialog);
			break;

		case PM_PE_INFO:
			::DialogBoxW(g_hInst, MAKEINTRESOURCE(IDD_DIALOG_PE), hWnd, PEDialog);
			break;

		case PM_DUMP: {
			WCHAR pId[16] = { 0 }, pName[MAX_PATH] = { 0 };

			int index = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
			
			ListView_GetItemText(g_hList, index, LV_PID, pId, sizeof(pId));
			ListView_GetItemText(g_hList, index, LV_PNAME, pName, sizeof(pName));

			// Convert .exe to .dmp extention
			WCHAR* dot = ::wcsrchr(pName, L'.');
			if (dot)
				*dot = L'\0';
			::wcscat_s(pName, L".dmp");

			if (SaveDumpFilePath(hWnd, pName))
				CreateDump(pId, pName);

			break;
		}

		case PM_INJECT: {
			WCHAR pId[16] = { 0 }, pName[MAX_PATH] = { 0 };
			int index = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
			ListView_GetItemText(g_hList, index, LV_PID, pId, sizeof(pId));

			DllInjection(_wtoi(pId)); break;
		}

		case ID_FILE_RELOAD:
			ListView_DeleteAllItems(g_hList);
			GetProcessList(g_hList);
			break;

		case ID_FILE_ABOUT:
			::MessageBoxW(nullptr, L"Process Security is a lightweight research tool in development for exploring Windows process internals and security features.", L"Process Security", MB_OK | MB_ICONINFORMATION);
		}
		break;

	case WM_DESTROY:
		::PostQuitMessage(0);
		break;

	default:
		return ::DefWindowProcW(hWnd, message, wParam, lParam);
	}
	return 0;
}


INT_PTR CALLBACK PropertiesDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG: {
		int index = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);

		WCHAR pName[MAX_PATH] = { 0 }, titleName[MAX_PATH + 32] = { 0 };;
		ListView_GetItemText(g_hList, index, LV_PID, g_pId, sizeof(g_pId));
		ListView_GetItemText(g_hList, index, LV_PNAME, pName, sizeof(pName));

		::wsprintfW(titleName, L"%ws (%ws) Properties", pName, g_pId);

		SetWindowTextW(hDlg, titleName);
		g_hPropertiesTab = GetDlgItem(hDlg, IDC_PROPERTIES_TAB);
		TCITEMW ti = { 0 };

		ti.mask = TCIF_TEXT;

		ti.pszText = (LPWSTR)L"Modules";
		TabCtrl_InsertItem(g_hPropertiesTab, TAB1, &ti);
		
		ti.pszText = (LPWSTR)L"Memory";
		TabCtrl_InsertItem(g_hPropertiesTab, TAB2, &ti);

		ti.pszText = (LPWSTR)L"Handles";
		TabCtrl_InsertItem(g_hPropertiesTab, TAB3, &ti);

		RECT rc;
		::GetClientRect(g_hPropertiesTab, &rc);
		TabCtrl_AdjustRect(g_hPropertiesTab, FALSE, &rc);

		::InitCommonControls();

		/**********************************************************************************************/

		// Initialize Tab 1

		g_hTabDialogModules = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, g_hPropertiesTab, 0, g_hInst, 0);

		g_hTabListViewModules = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, g_hTabDialogModules, 0, 0, 0);

		ListView_SetExtendedListViewStyle(g_hTabListViewModules, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		LVCOLUMNW col = { 0 };
		col.mask = LVCF_TEXT | LVCF_WIDTH;

		// Set Column for Tab 1
		col.pszText = const_cast<LPWSTR>(L"Name");
		col.cx = 150;
		ListView_InsertColumn(g_hTabListViewModules, 0, &col);

		col.pszText = const_cast<LPWSTR>(L"Base address");
		col.cx = 135;
		ListView_InsertColumn(g_hTabListViewModules, 1, &col);

		col.pszText = const_cast<LPWSTR>(L"Size");
		col.cx = 80;
		ListView_InsertColumn(g_hTabListViewModules, 2, &col);

		col.pszText = const_cast<LPWSTR>(L"Path");
		col.cx = 345;
		ListView_InsertColumn(g_hTabListViewModules, 3, &col);

		GetProcessModuleInformation(g_hTabListViewModules, _wtoi(g_pId));

		/**********************************************************************************************/

		// Initialize Tab 2

		g_hTabDialogMemory = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, g_hPropertiesTab, 0, g_hInst, 0);

		g_hTabListViewMemory = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, g_hTabDialogMemory, 0, 0, 0);

		ListView_SetExtendedListViewStyle(g_hTabListViewMemory, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		// Set Column for Tab 2
		col.pszText = const_cast<LPWSTR>(L"Base address");
		col.cx = 170;
		ListView_InsertColumn(g_hTabListViewMemory, 0, &col);

		col.pszText = const_cast<LPWSTR>(L"Type");
		col.cx = 190;
		ListView_InsertColumn(g_hTabListViewMemory, 1, &col);

		col.pszText = const_cast<LPWSTR>(L"Size");
		col.cx = 200;
		ListView_InsertColumn(g_hTabListViewMemory, 2, &col);

		col.pszText = const_cast<LPWSTR>(L"Protection");
		col.cx = 150;
		ListView_InsertColumn(g_hTabListViewMemory, 3, &col);

		GetMemoryBasicInformation(g_hTabListViewMemory, _wtoi(g_pId));

		/**********************************************************************************************/

		// Initialize Tab 3

		g_hTabDialogHandle = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, g_hPropertiesTab, 0, g_hInst, 0);

		g_hTabListViewHandle = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, g_hTabDialogHandle, 0, 0, 0);

		ListView_SetExtendedListViewStyle(g_hTabListViewHandle, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		// Set Column for Tab 3
		col.pszText = const_cast<LPWSTR>(L"Type");
		col.cx = 170;
		ListView_InsertColumn(g_hTabListViewHandle, 0, &col);

		col.pszText = const_cast<LPWSTR>(L"Name");
		col.cx = 340;
		ListView_InsertColumn(g_hTabListViewHandle, 1, &col);

		col.pszText = const_cast<LPWSTR>(L"Handle");
		col.cx = 100;
		ListView_InsertColumn(g_hTabListViewHandle, 2, &col);

		col.pszText = const_cast<LPWSTR>(L"Granted Access");
		col.cx = 100;
		ListView_InsertColumn(g_hTabListViewHandle, 3, &col);

		GetHandleObjectInformation(g_hTabListViewHandle, _wtoi(g_pId));
	}
	break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_PROPERTIES_REFRESH:
			ListView_DeleteAllItems(g_hTabListViewMemory);
			ListView_DeleteAllItems(g_hTabListViewModules);
			ListView_DeleteAllItems(g_hTabListViewHandle);
 			GetMemoryBasicInformation(g_hTabListViewMemory, _wtoi(g_pId));
			GetProcessModuleInformation(g_hTabListViewModules, _wtoi(g_pId));
			GetHandleObjectInformation(g_hTabListViewHandle, _wtoi(g_pId));
		}
		break;

	case WM_NOTIFY: {
		if (((LPNMHDR)lParam)->idFrom == IDC_PROPERTIES_TAB && ((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
			int i = TabCtrl_GetCurSel(g_hPropertiesTab);

			::ShowWindow(g_hTabDialogModules, i == 0 ? SW_SHOW : SW_HIDE);
			::ShowWindow(g_hTabDialogMemory, i == 1 ? SW_SHOW : SW_HIDE);
			::ShowWindow(g_hTabDialogHandle, i == 2 ? SW_SHOW : SW_HIDE);
		}
		break;
	}

	case WM_CLOSE:
		::EndDialog(hDlg, 0);
		g_hPropertiesTab      = nullptr;
		g_hTabDialogModules   = nullptr;
		g_hTabListViewModules = nullptr;
		g_hTabDialogMemory    = nullptr;
		g_hTabListViewMemory  = nullptr;
		g_hTabDialogHandle    = nullptr;
		g_hTabListViewHandle  = nullptr;
	}

	return (INT_PTR)FALSE;
}


INT_PTR CALLBACK PEBDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG: {

		/**********************************************************************************************/
		// Initialize List View

		RECT rc;
		::GetClientRect(hDlg, &rc);
		TabCtrl_AdjustRect(hDlg, FALSE, &rc);

		::InitCommonControls();

		HWND hPebDialog = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, hDlg, 0, g_hInst, 0);

		HWND hTabListView = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, hPebDialog, 0, 0, 0);

		ListView_SetExtendedListViewStyle(hTabListView, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		LVCOLUMNW col = { 0 };
		col.mask = LVCF_TEXT | LVCF_WIDTH;

		col.pszText = const_cast<LPWSTR>(L"Name");
		col.cx = 150;
		ListView_InsertColumn(hTabListView, TAB_LV_OPTIONAL_NAME, &col);

		col.pszText = const_cast<LPWSTR>(L"Value");
		col.cx = 470;
		ListView_InsertColumn(hTabListView, TAB_LV_OPTIONAL_VALUE, &col);

		/**********************************************************************************************/
		// Get PEB Info

		WCHAR pId[16] = { 0 }, pName[MAX_PATH] = { 0 };
		int index = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);

		ListView_GetItemText(g_hList, index, LV_PID, pId, sizeof(pId));
		ListView_GetItemText(g_hList, index, LV_PNAME, pName, sizeof(pName));

		GetPebInfo(hTabListView, pId, pName);
	}
	break;

	case WM_CLOSE:
		::EndDialog(hDlg, 0);
	}

	return (INT_PTR)FALSE;
}


INT_PTR CALLBACK PEDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_INITDIALOG: {
		g_hPeTab = ::GetDlgItem(hDlg, IDC_TAB_PE);
		TCITEMW ti = { 0 };
		ti.mask = TCIF_TEXT;

		ti.pszText = (LPWSTR)L"Optinal Header";
		TabCtrl_InsertItem(g_hPeTab, TAB1, &ti);

		ti.pszText = (LPWSTR)L"Import Table";
		TabCtrl_InsertItem(g_hPeTab, TAB2, &ti);

		RECT rc;
		::GetClientRect(g_hPeTab, &rc);
		TabCtrl_AdjustRect(g_hPeTab, FALSE, &rc);

		::InitCommonControls();

		/**********************************************************************************************/

		// Initialize Tab 1
		g_hTabDialogOptional = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, g_hPeTab, 0, g_hInst, 0);

		HWND hTabListViewOptional = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, g_hTabDialogOptional, 0, 0, 0);

		ListView_SetExtendedListViewStyle(hTabListViewOptional, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		LVCOLUMNW col = { 0 };
		col.mask = LVCF_TEXT | LVCF_WIDTH;

		// Set Column for Tab 1
		col.pszText = const_cast<LPWSTR>(L"Name");
		col.cx = 200;
		ListView_InsertColumn(hTabListViewOptional, TAB_LV_OPTIONAL_NAME, &col);

		col.pszText = const_cast<LPWSTR>(L"Value");
		col.cx = 200;
		ListView_InsertColumn(hTabListViewOptional, TAB_LV_OPTIONAL_VALUE, &col);

		/**********************************************************************************************/

		// Initialize Tab 2
		g_hTabDialogImport = ::CreateWindowExW(0, L"STATIC", L"", WS_CHILD,
			rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, g_hPeTab, 0, g_hInst, 0);

		HWND hTabListViewImport = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT,
			0, 0, rc.right, rc.bottom - 15, g_hTabDialogImport, 0, 0, 0);

		ListView_SetExtendedListViewStyle(hTabListViewImport, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

		// Set Column for Tab 2
		col.pszText = const_cast<LPWSTR>(L"DLL");
		col.cx = 160;
		ListView_InsertColumn(hTabListViewImport, TAB_LV_IMPORT_DLLNAME, &col);

		col.pszText = const_cast<LPWSTR>(L"Function");
		col.cx = 210;
		ListView_InsertColumn(hTabListViewImport, TAB_LV_IMPORT_FUNCNAME, &col);

		col.pszText = const_cast<LPWSTR>(L"Ordinal");
		col.cx = 75;
		ListView_InsertColumn(hTabListViewImport, TAB_LV_IMPORT_FUNC_ORDINAL, &col);

		/**********************************************************************************************/

		// Get Process Info (Process Name, PID)
		WCHAR pPath[MAX_PATH];
		int index = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
		ListView_GetItemText(g_hList, index, LV_PATH, pPath, sizeof(pPath));

		/**********************************************************************************************/

		// TAB_HANDLES define in PEInformation.h
		TAB_HANDLES tabHandles = { 0 };
		tabHandles.hTabListViewOptional = hTabListViewOptional;
		tabHandles.hTabListViewImport = hTabListViewImport;

		GetPeInfo(&tabHandles, pPath);

		break;
	}

	case WM_NOTIFY: {
		if (((LPNMHDR)lParam)->idFrom == IDC_TAB_PE && ((LPNMHDR)lParam)->code == TCN_SELCHANGE) {
			int i = TabCtrl_GetCurSel(g_hPeTab);

			::ShowWindow(g_hTabDialogOptional, i == 0 ? SW_SHOW : SW_HIDE);
			::ShowWindow(g_hTabDialogImport, i == 1 ? SW_SHOW : SW_HIDE);
		}
		break;
	}

	case WM_CLOSE:
		::EndDialog(hDlg, 0);
		g_hPeTab             = nullptr;
		g_hTabDialogOptional = nullptr;
		g_hTabDialogImport   = nullptr;
		break;
	}

	return (INT_PTR)FALSE;
}


void AddColumns(HWND g_hList)
{
	LVCOLUMNW col = { 0 };
	col.mask = LVCF_TEXT | LVCF_WIDTH;

	col.pszText = const_cast<LPWSTR>(L"Process Name");
	col.cx = 150;
	ListView_InsertColumn(g_hList, LV_PNAME, &col);

	col.pszText = const_cast<LPWSTR>(L"PID");
	col.cx = 70;
	ListView_InsertColumn(g_hList, LV_PID, &col);

	col.pszText = const_cast<LPWSTR>(L"PPID");
	col.cx = 70;
	ListView_InsertColumn(g_hList, LV_PPID, &col);

	col.pszText = const_cast<LPWSTR>(L"Protection");
	col.cx = 140;
	ListView_InsertColumn(g_hList, LV_PROTECT, &col);

	col.pszText = const_cast<LPWSTR>(L"User name");
	col.cx = 200;
	ListView_InsertColumn(g_hList, LV_USER, &col);

	col.pszText = const_cast<LPWSTR>(L"ASLR");
	col.cx = 60;
	ListView_InsertColumn(g_hList, LV_ASLR, &col);

	col.pszText = const_cast<LPWSTR>(L"DEP");
	col.cx = 60;
	ListView_InsertColumn(g_hList, LV_DEP, &col);

	col.pszText = const_cast<LPWSTR>(L"CFG");
	col.cx = 60;
	ListView_InsertColumn(g_hList, LV_CFG, &col);

	col.pszText = const_cast<LPWSTR>(L"Path");
	col.cx = 450;
	ListView_InsertColumn(g_hList, LV_PATH, &col);
}


void AddItem(HWND g_hList, int index, PSYSTEM_PROCESS_INFORMATION pi, wchar_t* path, PMITIGATION m, PPROTECTION p, PUSERINFO u)
{
	// Process Basic Information
	wchar_t szPid[16] = { 0 };
	::wsprintfW(szPid, L"%lu", HandleToULong(pi->UniqueProcessId));

	wchar_t szPpid[16] = { 0 };
	::wsprintfW(szPpid, L"%lu", HandleToULong(pi->InheritedFromUniqueProcessId));

	// Process Protection Information
	wchar_t szProtection[64] = { 0 };
	::wsprintfW(szProtection, L"%ws %ws", p->Type, p->Signer);

	// Process Username Information
	wchar_t szUsername[UNLEN + DNLEN + 2] = { 0 };
	if (u->UserName[0] != L'\0')
		::wsprintfW(szUsername, L"%ws\\%ws", u->DomainName, u->UserName);

	// Process Mitigation Information
	wchar_t szASLR[8] = { 0 };
	if (m->ASLRPolicy == -1) ::wcsncpy_s(szASLR, L"n/a", 5);
	else ::wsprintfW(szASLR, L"%ws", (m->ASLRPolicy == 1 ? L"ASLR" : L""));

	wchar_t szDEP[8] = { 0 };
	if (m->DEPPolicy == -1) ::wcsncpy_s(szDEP, L"n/a", 5);
	else ::wsprintfW(szDEP, L"%ws", (m->DEPPolicy == 1 ? L"DEP" : L""));

	wchar_t szCFG[8] = { 0 };
	if (m->ControlFlowGuardPolicy == -1) ::wcsncpy_s(szCFG, L"n/a", 5);
	else ::wsprintfW(szCFG, L"%ws", (m->ControlFlowGuardPolicy == 1 ? L"CFG" : L""));

	// Set Items
	PPROC_ITEM data = (PPROC_ITEM)malloc(sizeof(PROC_ITEM));

	if (pi->ImageName.Buffer) ::wcscpy_s(data->name, pi->ImageName.Buffer);
	else if (!(pi->ImageName.Buffer) && HandleToULong(pi->UniqueProcessId) == 0)
		::wcscpy_s(data->name, L"System Idle Process");

	data->pid = HandleToULong(pi->UniqueProcessId);
	data->ppid = HandleToULong(pi->InheritedFromUniqueProcessId);
	data->originalIndex = index;

	LVITEMW item = { 0 };
	item.mask = LVIF_TEXT | LVIF_PARAM;
	item.iItem = index;
	item.pszText = data->name;
	item.lParam = (LPARAM)data;

	ListView_InsertItem(g_hList, &item);
	ListView_SetItemText(g_hList, index, LV_PID, szPid);
	ListView_SetItemText(g_hList, index, LV_PPID, szPpid);
	ListView_SetItemText(g_hList, index, LV_PATH, path);

	ListView_SetItemText(g_hList, index, LV_PROTECT, szProtection);
	ListView_SetItemText(g_hList, index, LV_USER, szUsername);

	ListView_SetItemText(g_hList, index, LV_ASLR, szASLR);
	ListView_SetItemText(g_hList, index, LV_DEP, szDEP);
	ListView_SetItemText(g_hList, index, LV_CFG, szCFG);

	if (data)
		free(data);
}


void GetProcessList(HWND g_hList)
{
	HMODULE hNtdll = ::LoadLibrary(L"ntdll.dll");
	if (hNtdll != NULL) {
		auto NtQuerySystemInformation = (NtQuerySystemInformation_t)::GetProcAddress(hNtdll, "NtQuerySystemInformation");

		::FreeLibrary(hNtdll);

		HANDLE hHeap = ::GetProcessHeap();
		PVOID buffer = NULL;
		ULONG bufferSize = 0x10000;
		ULONG returnLen = 0;
		NTSTATUS status;

		for (;;) {

			if (buffer) {
				::HeapFree(hHeap, 0, buffer);
				buffer = NULL;
			}

			buffer = ::HeapAlloc(hHeap, HEAP_ZERO_MEMORY, bufferSize);
			if (!buffer) return;

			status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLen);
			if (status == STATUS_SUCCESS) break;

			else if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
				if (returnLen > bufferSize)
					bufferSize = (returnLen + (1 << 12));
				else bufferSize *= 2;
			}

			else {
				if (buffer) ::HeapFree(hHeap, 0, buffer);
				return;
			}
		}

		auto process = (PSYSTEM_PROCESS_INFORMATION)buffer;
		int processCount = 0;

		for (;;processCount++) {

			WCHAR path[512] = { 0 };
			GetProcessFilePath(HandleToULong(process->UniqueProcessId), path, nullptr, FALSE);

			MITIGATION m = { 0 };
			GetProcessMitigation(HandleToULong(process->UniqueProcessId), &m);

			PROTECTION p = { 0 };
			GetProcessProtection(HandleToULong(process->UniqueProcessId), &p);

			USERINFO u = { 0 };
			GetProcessUserInfo(HandleToULong(process->UniqueProcessId), &u, nullptr, FALSE);

			AddItem(g_hList, processCount, process, path, &m, &p, &u);

			if (process->NextEntryOffset == 0) break;
			process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)process + process->NextEntryOffset);
		}

		::HeapFree(hHeap, 0, buffer);
	}
}


void SetColor(LPNMLVCUSTOMDRAW plvcd)
{
	int itemIndex = (int)plvcd->nmcd.dwItemSpec;
	WCHAR username[UNLEN + DNLEN + 2] = { 0 };
	WCHAR protection[64] = { 0 };
	WCHAR pID[32] = { 0 };

	ListView_GetItemText(g_hList, itemIndex, LV_USER, username, sizeof(username));
	ListView_GetItemText(g_hList, itemIndex, LV_PROTECT, protection, sizeof(protection));
	ListView_GetItemText(g_hList, itemIndex, LV_PID, pID, sizeof(pID));

	if (!_wcsnicmp(username, L"NT AUTHORITY\\SYSTEM", sizeof(username)))
		plvcd->clrTextBk = RGB(170, 204, 255);

	if (!_wcsnicmp(username, L"NT AUTHORITY\\LOCAL SERVICE", sizeof(username)) || !_wcsnicmp(username, L"NT AUTHORITY\\NETWORK SERVICE", sizeof(username)))
		plvcd->clrTextBk = RGB(204, 255, 255);

	if (protection[0] != L'\x20')
		plvcd->clrTextBk = RGB(255, 170, 0);

	if (IsOwnProcess(_wtoi(pID)))
		plvcd->clrTextBk = RGB(255, 255, 170);

	if (IsProcess32(_wtoi(pID)))
		plvcd->clrTextBk = RGB(188, 143, 143);
	
}


void ShowPopupMenu(HWND hWnd)
{
	HMENU hPopupMenu = ::CreatePopupMenu();
	
	::AppendMenuW(hPopupMenu, MF_STRING, PM_PROPERTIES, L"Properties");
	::AppendMenuW(hPopupMenu, MF_STRING, PM_PEB_INFO, L"PEB Information");
	::AppendMenuW(hPopupMenu, MF_STRING, PM_PE_INFO, L"PE Information");
	::AppendMenuW(hPopupMenu, MF_STRING, PM_DUMP, L"Create Dump");
	::AppendMenuW(hPopupMenu, MF_STRING, PM_INJECT, L"Inject DLL");

	POINT pt = { 0 };

	::GetCursorPos(&pt);
	::TrackPopupMenu(hPopupMenu, TPM_LEFTALIGN | TPM_TOPALIGN, pt.x, pt.y, 0, hWnd, nullptr);
	::DestroyMenu(hPopupMenu);
}


int CALLBACK CompareFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	PPROC_ITEM p1 = (PPROC_ITEM)lParam1;
	PPROC_ITEM p2 = (PPROC_ITEM)lParam2;

	int column = (int)lParamSort;
	int result = 0;

	switch (column)
	{
	case LV_PNAME:
		result = wcscmp(p1->name, p2->name); break;
		
	case LV_PID:
		result = (int)(p1->pid - p2->pid); break;
	}

	if (g_SortState == 2) // Descending
		result = -result;

	return result;
}


int CALLBACK CompareOriginal(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	PPROC_ITEM p1 = (PPROC_ITEM)lParam1;
	PPROC_ITEM p2 = (PPROC_ITEM)lParam2;

	if (p1->originalIndex < p2->originalIndex)
		return -1;
	if (p1->originalIndex > p2->originalIndex)
		return 1;

	return 0;
}