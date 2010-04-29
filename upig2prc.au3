;created by xiangwei 
;mail 31531640@qq.com
;http://17memo.com


#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_icon=upig2prc.ico
#AutoIt3Wrapper_Res_Comment=upig2prc by 31531640@qq.com http://17memo.com
#AutoIt3Wrapper_Res_Description=upig2prc txtlrf
#AutoIt3Wrapper_Res_Fileversion=9.2.25.24
#AutoIt3Wrapper_Res_Language=2052
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <ProgressConstants.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>

#Region ### START Koda GUI section ### Form=d:\3_appdata\microsoft\desktop\upig2prc\新版\ui.kxf
<<<<<<< HEAD
$dlgMain = GUICreate("upig2prc (10.4.27.1) 将Txt批量转换到prc(Kindle电子书)", 640, 465, 193, 115, -1, 0x00000018)
$ctlEditOutput = GUICtrlCreateEdit("", 8, 116, 617, 337, BitOR($ES_AUTOVSCROLL,$ES_AUTOHSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_HSCROLL,$WS_VSCROLL))
=======
$dlgMain = GUICreate("upig2prc (10.4.28.5) 将Txt批量转换到prc(Kindle电子书)", 640, 415, 193, 115, -1, 0x00000018)
$ctlEditOutput = GUICtrlCreateEdit("", 8, 64, 617, 337, BitOR($ES_AUTOVSCROLL,$ES_AUTOHSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_HSCROLL,$WS_VSCROLL))
>>>>>>> 5687949cc61bf751ed702ae90f8554b32e70de2e
GUICtrlSetData(-1, "")
$ctlEditFileInput = GUICtrlCreateEdit("", 8, 116, 617, 337, BitOR($ES_AUTOVSCROLL,$ES_AUTOHSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_HSCROLL,$WS_VSCROLL))
GUICtrlSetData(-1, "")
$ctlEditHelp = GUICtrlCreateEdit("", 8, 116, 617, 337, BitOR($ES_AUTOVSCROLL,$ES_AUTOHSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_HSCROLL,$WS_VSCROLL))
GUICtrlSetData(-1, "")
$ctlProgressTotal = GUICtrlCreateProgress(56, 6, 358, 16)
$ctlProgressInd = GUICtrlCreateProgress(488, 6, 134, 16)
;$ctlCheckEnglishOnly = GUICtrlCreateCheckbox("纯英文", 440, 34, 65, 17)
;$ctlComboEncoding = GUICtrlCreateCombo("普通编码", 70, 34, 79, 25)
;GUICtrlSetData(-1, "普通编码|Unicode(UTF-16)|UTF-8")
;$ctlEditParamTxt2lrf = GUICtrlCreateInput("", 267, 35, 151, 21)
;$ctlEditPrefix = GUICtrlCreateInput("", 70, 66, 79, 21)
$Label3 = GUICtrlCreateLabel("总进度", 8, 8, 40, 17)
;$Label5 = GUICtrlCreateLabel("前缀：", 30, 68, 40, 17)
$ctlEditPathOutput = GUICtrlCreateInput("", 267, 67, 151, 21)
;$Label1 = GUICtrlCreateLabel("", 237, 64, 4, 4)
;$Label6 = GUICtrlCreateLabel("", 272, 106, 4, 4)
;$Label7 = GUICtrlCreateLabel("TXT2LRF参数：", 180, 37, 87, 17)
$ctlCheckUseOutputPath = GUICtrlCreateCheckbox("输出路径：", 180, 70, 81, 17)
;$Label2 = GUICtrlCreateLabel("编码格式：", 6, 37, 64, 17)
;$ctlBtnTest = GUICtrlCreateButton("ctlBtnTest", 432, 16, 35, 17, 0)
;$ctlCheckAutoParagraph = GUICtrlCreateCheckbox("智能分段", 534, 34, 89, 17)
$Label4 = GUICtrlCreateLabel("子进度", 440, 8, 40, 17)
$ctlBtnVist17memo = GUICtrlCreateButton("去和书友交流", 438, 64, 107, 25, 0)
$ctlBtnHelp = GUICtrlCreateButton("帮助", 552, 64, 67, 25, 0)
$Label8 = GUICtrlCreateLabel("请将txt文件或文件夹拖入到下面的文本框中。upig出品(31531640@qq.com)", 8,36, 400, 17)
GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

Global $helpStr = StringFormat("　请将txt文件或文件夹拖到此文本框中，支持多个一起拖，只支持遍历一级文件夹\r\n\r\n联系与反馈，常见问题解答：\r\n　网站：http://17memo.com\r\n　邮箱或QQ：31531640@qq.com\r\n")


#include <File.au3>
#include <Array.au3>
#include <Process.au3>
#include <Constants.au3>
#include <GuiEdit.au3>
#include <GuiStatusBar.au3>
#include <GuiConstantsEx.au3>
#include <WindowsConstants.au3>
#include <EditConstants.au3>
#include <StaticConstants.au3>
#include <Debug.au3>
#include <IE.au3>

AutoItSetOption("MustDeclareVars", 1)

Global $g_oIE = _IECreate ("http://17memo.com/forums/forumdisplay.php?fid=2&filter=type&typeid=2", 0, 0, 0)

Global $g_errCount = 0
Global $g_totalFileCount = 0;
Global $g_tempFileDir = @ScriptDir & "\__temp_upig_"
Global $g_inifileName = @ScriptDir & "\upig2prc.ini"
Global $g_iniSection = "Setting20"
;GUICtrlSetData($ctlEditPrefix,			IniRead($g_inifileName, $g_iniSection, "$ctlEditPrefix", 			"e."))
;GUICtrlSetData($ctlComboEncoding, 	" ",IniRead($g_inifileName, $g_iniSection, "$ctlComboEncoding", 		"普通编码"))
GUICtrlSetData($ctlEditPathOutput, 		IniRead($g_inifileName, $g_iniSection, "$ctlEditPathOutput", 		""))
;GUICtrlSetData($ctlEditParamTxt2lrf, 	IniRead($g_inifileName, $g_iniSection, "$ctlEditParamTxt2lrf", 		"--author=upig2prc --left-margin=0 --right-margin=0 --top-margin=0 --bottom-margin=0 --override-css=""code {font-family: 'Swis721 BT'}"""))
Global $g_bEngilsh = 					IniRead($g_inifileName, $g_iniSection, "$g_bEngilsh", 			False)
Global $g_bUseOutputPath= 				IniRead($g_inifileName, $g_iniSection, "$g_bUseOutputPath", 	False)
Global $g_ToolName = 					IniRead($g_inifileName, $g_iniSection, "$g_ToolName", 			"upigcmd")
Global $g_titleMaxStrLen = 				IniRead($g_inifileName, $g_iniSection, "$g_titleMaxStrLen", 	70)
Global $g_titleWord = 					IniRead($g_inifileName, $g_iniSection, "$g_titleWord", 			"(?i)CHAPTER|.{0,1}第{0,1}[ 　]{0,10}[序0-9０１２３４５６７８９〇一二三四五六七八九个十百千万零壹贰叁肆伍陆柒捌玖拾佰仟萬]{1,15}[ 　]{0,10}[章|回|卷|篇|节|部|集].{0,1}")
Global $g_titleWordInvallid = 			IniRead($g_inifileName, $g_iniSection, "$g_titleWordInvallid", 	"回合|节课|部分")
Global $g_titleWordPre = 				IniRead($g_inifileName, $g_iniSection, "$g_titleWordPre", 		"[文第０１２３４５６７８９　〇一二三四五六七八九个十百千万零壹贰叁肆伍陆柒捌玖拾佰仟萬章回卷篇节部集]")
Global $g_chptMaxChrcters = 			IniRead($g_inifileName, $g_iniSection, "$g_chptMaxChrcters", 	500000)
Global $g_chptMinChrcters = 			IniRead($g_inifileName, $g_iniSection, "$g_chptMinChrcters", 	400)
Global $g_bInsertTOC= 					IniRead($g_inifileName, $g_iniSection, "$g_bInsertTOC", 		True)
Global $g_bUsePublisher = 				IniRead($g_inifileName, $g_iniSection, "$g_bUsePublisher", 		True)
Global $g_bRelease = 					IniRead($g_inifileName, $g_iniSection, "$g_bRelease", 			True)
Global $g_bFmtIndent = 					IniRead($g_inifileName, $g_iniSection, "$g_bFmtIndent", 		True)
Global $g_bFmtNewLine = 				IniRead($g_inifileName, $g_iniSection, "$g_bFmtNewLine", 		True)
Global $g_bAutoParagraph= 				IniRead($g_inifileName, $g_iniSection, "$g_bAutoParagraph", 	False)
Global $g_maxParagraphSize = 			IniRead($g_inifileName, $g_iniSection, "$g_maxParagraphSize", 	5000)
Global $g_reg = 						IniRead($g_inifileName, $g_iniSection, "$g_reg", 				-1)


;for debug
If $g_bRelease==False Then _DebugSetup("upig2prc")

;GUICtrlSetState(

;"upig2prc工具用于将中文txt文件批量转换为lrf文件" & @CRLF & @CRLF & "请将需要转换的文件或文件夹拖进来" & @CRLF & "支持多个文件，文件夹一起拖" & @CRLF &"只支持遍历一级文件夹"&@CRLF&@CRLF &@CRLF &@CRLF &@CRLF &@CRLF & "注意:运行本软件先得安装Calibre(http://calibre.kovidgoyal.net)" & @CRLF & "说明:文件转换出错或出现乱码后可尝试修改GBK等参数" & @CRLF & "联系:有什么Bug欢迎反馈给我(31531640@qq.com)"
GUICtrlSetState($ctlEditFileInput, $GUI_DROPACCEPTED)
GUICtrlSetData($ctlEditOutput, $helpStr)
GUICtrlSetData($ctlEditFileInput, "")
GUICtrlSetData($ctlEditHelp, $helpStr)
;GUICtrlSetState($ctlBtnTest, $GUI_HIDE)

If $g_bEngilsh==True Then 
;	GUICtrlSetState($ctlCheckEnglishOnly, $GUI_CHECKED)
Else
;	GUICtrlSetState($ctlCheckEnglishOnly, $GUI_UNCHECKED)
	;MsgBox(0, "$g_bEngilsh", $g_bEngilsh)
EndIf

If $g_bAutoParagraph==True Then
;	GUICtrlSetState($ctlCheckAutoParagraph, $GUI_CHECKED)
Else
;	GUICtrlSetState($ctlCheckAutoParagraph, $GUI_UNCHECKED)
EndIf


If $g_bUseOutputPath==True Then 
	GUICtrlSetState($ctlCheckUseOutputPath, $GUI_CHECKED)
	GUICtrlSetState($ctlEditPathOutput, $GUI_ENABLE)
Else
	GUICtrlSetState($ctlCheckUseOutputPath, $GUI_UNCHECKED)
	GUICtrlSetState($ctlEditPathOutput, $GUI_DISABLE)
EndIf

;DirCreate($g_tempFileDir)

If $g_reg ==-1 Then
	RegWrite("HKEY_CLASSES_ROOT\txtfile\shell\A用&upig2prc转换\command", "", "REG_SZ", @ScriptFullPath&" ""%1""")
	RegWrite("HKEY_CLASSES_ROOT\txtfile\shell\A用&upig2prc转换\", "", "REG_SZ", "用&upig2prc转换")
	RegWrite("HKEY_CLASSES_ROOT\Folder\shell\A用&upig2prc转换\command", "", "REG_SZ", @ScriptFullPath&" ""%1""")
	RegWrite("HKEY_CLASSES_ROOT\Folder\shell\A用&upig2prc转换\", "", "REG_SZ", "用&upig2prc转换")
	$g_reg = 1
EndIf

If $g_reg ==0 Then
	RegDelete("HKEY_CLASSES_ROOT\txtfile\shell\A用&upig2prc转换\")
	RegDelete("HKEY_CLASSES_ROOT\Folder\shell\A用&upig2prc转换\")
EndIf

Global $g_BookListReady = False
Global $g_BookListShowed = False

If $CmdLine[0]<>0 Then
	ConvertDirFileMultiLine($CmdLine[1]&@CRLF);Cmdline
	$g_BookListShowed = True
EndIf

;GUICtrlRead($ctlEditOutput)<>""


While 1
	Local $msg = GUIGetMsg()
	
	If $g_BookListReady==True Then
		If $g_BookListShowed==False then 
			ShowBookList()
			$g_BookListShowed = True
			$g_BookListReady = False
		EndIf
	Else
		if(_IELoadWait ($g_oIE, 0, 1))==1 Then
			$g_BookListReady = True
		EndIf		
	EndIf
		
	Switch $msg	
		;if $msg<>0 Then MsgBox(0, "kdk", "kdk33d")
		case  $GUI_EVENT_DROPPED 
			;GUICtrlSetState($ctlEditHelp, $GUI_HIDE + $GUI_DISABLE)		
			Local $fileTempInput = GUICtrlRead($ctlEditFileInput)
			GUICtrlSetData($ctlEditFileInput, "")
			$g_BookListShowed = True
			$g_BookListReady = True
			ConvertDirFileMultiLine($fileTempInput)	
		case $GUI_EVENT_CLOSE 
			;@todo write ini when close
;			IniWrite($g_inifileName, $g_iniSection, "$ctlEditPrefix", GUICtrlRead($ctlEditPrefix))
;			IniWrite($g_inifileName, $g_iniSection, "$ctlComboEncoding", GUICtrlRead($ctlComboEncoding))
;			IniWrite($g_inifileName, $g_iniSection, "$ctlEditParamTxt2lrf", GUICtrlRead($ctlEditParamTxt2lrf))
			IniWrite($g_inifileName, $g_iniSection, "$ctlEditPathOutput", GUICtrlRead($ctlEditPathOutput))
			IniWrite($g_inifileName, $g_iniSection, "$g_ToolName", $g_ToolName )
			IniWrite($g_inifileName, $g_iniSection, "$g_bEngilsh", $g_bEngilsh )
			IniWrite($g_inifileName, $g_iniSection, "$g_bUseOutputPath", $g_bUseOutputPath )
			IniWrite($g_inifileName, $g_iniSection, "$g_titleMaxStrLen", $g_titleMaxStrLen )
			IniWrite($g_inifileName, $g_iniSection, "$g_titleWord", $g_titleWord )
			IniWrite($g_inifileName, $g_iniSection, "$g_titleWordInvallid", $g_titleWordInvallid )
			IniWrite($g_inifileName, $g_iniSection, "$g_titleWordPre", $g_titleWordPre )
			IniWrite($g_inifileName, $g_iniSection, "$g_chptMaxChrcters", $g_chptMaxChrcters )
			IniWrite($g_inifileName, $g_iniSection, "$g_chptMinChrcters", $g_chptMinChrcters )
			IniWrite($g_inifileName, $g_iniSection, "$g_bInsertTOC", $g_bInsertTOC)
			IniWrite($g_inifileName, $g_iniSection, "$g_bUsePublisher", $g_bUsePublisher )
			IniWrite($g_inifileName, $g_iniSection, "$g_bRelease", $g_bRelease )
			IniWrite($g_inifileName, $g_iniSection, "$g_bFmtIndent", $g_bFmtIndent )
			IniWrite($g_inifileName, $g_iniSection, "$g_bFmtNewLine", $g_bFmtNewLine )
			IniWrite($g_inifileName, $g_iniSection, "$g_bAutoParagraph", $g_bAutoParagraph )
			IniWrite($g_inifileName, $g_iniSection, "$g_maxParagraphSize", $g_maxParagraphSize )		
			IniWrite($g_inifileName, $g_iniSection, "$g_reg", $g_reg )
			ExitLoop
		case $ctlCheckUseOutputPath
			$g_bUseOutputPath = ($g_bUseOutputPath==False)
			if $g_bUseOutputPath==True Then
				GUICtrlSetState($ctlEditPathOutput, $GUI_ENABLE)
			Else
				GUICtrlSetState($ctlEditPathOutput, $GUI_DISABLE)	
			EndIf		
		case $ctlBtnVist17memo
			ShellExecute ("http://17memo.com/forums/forumdisplay.php?fid=2")
		case  $ctlBtnHelp
			$g_BookListShowed = True
			$g_BookListReady = True
			GUICtrlSetData($ctlEditOutput, "")
			IceLogMsg($helpStr)
	EndSwitch
WEnd

Func ShowBookList()
	GUICtrlSetData($ctlEditOutput, "")
	IceLogMsg("===========================================")
	IceLogMsg(GetBookList())
	IceLogMsg("===========================================")
	IceLogMsg("以下条目是近期书评...欢迎各位书友交流 17memo.com")
EndFunc

Func AutoTest()
	MsgBox(0, "", "kdkd")
EndFunc

Func GetRealEncoding($strCode)
	If $strCode == "GBK" Then return "GB18030"
	If $strCode == "普通编码" Then return "GB18030"
	If $strCode == "Unicode(UTF-16)" Then return "utf-16"
	If $strCode == "UTF-8" Then return "utf-8"
	return $strCode	
EndFunc

Func IceLogMsg($LogStr)
	Local $tempLine = $LogStr&@CRLF&GUICtrlRead($ctlEditOutput)
	GUICtrlSetData($ctlEditOutput, $tempLine)
	GUICtrlSetData($ctlEditHelp, $tempLine)	
EndFunc

Func ConvertFile($inputFileName)	
	Local $szDrive, $szDir, $inputFileTitle, $inputFileExt
	_PathSplit($inputFileName, $szDrive, $szDir, $inputFileTitle, $inputFileExt)
	
	
	Local $workPath = $szDrive&$szDir

<<<<<<< HEAD
	Local $pathOutPut = GUICtrlRead($ctlEditPathOutput)&"\"
	If $g_bUseOutputPath==False Then $pathOutPut=$workPath
	If StringIsSpace(GUICtrlRead($ctlEditPathOutput)) Then $pathOutPut=""
	If $inputFileExt == ".prc" Or $inputFileExt == ".exe" Then Return
=======
;	Local $pathOutPut = GUICtrlRead($ctlEditPathOutput)&"\"
;	If $g_bUseOutputPath==False Then $pathOutPut=$workPath
;	If StringIsSpace(GUICtrlRead($ctlEditPathOutput)) Then $pathOutPut=""
	If $inputFileExt == ".prc" Or $inputFileExt == ".exe" Or $inputFileExt == ".mobi" Then Return
>>>>>>> 5687949cc61bf751ed702ae90f8554b32e70de2e
	$g_totalFileCount += 1
	IceLogMsg("["&$g_totalFileCount&"]  正在转换中，请稍候: " & $inputFileTitle & $inputFileExt)
	
	
	
<<<<<<< HEAD
	Local $cvtFileName = 	$inputFileName
	Local $outputParam=""
	If $pathOutPut<>"" Then $outputParam = " --output=""" & $pathOutPut & $inputFileTitle & ".prc"" "
=======
	Local $cvtFileName = 	StringReplace($inputFileName, "'", "\'")
>>>>>>> 5687949cc61bf751ed702ae90f8554b32e70de2e

 ;   Run it! upigcmd.exe
;	Local $cmd = @ComSpec & " /c " & $g_ToolName &" "& $encodingParm & $publisher & $debugParam & $outputParam & GUICtrlRead($ctlEditParamTxt2lrf) & " """ & $cvtFileName & """ " &$debugParam2   
;	ConsoleWrite($cmd)
	Local $script_path = FileGetShortName(@ScriptDir)

	Local $cmd = @ComSpec & " /c """"" & $script_path& '\'&$g_ToolName &""" "& $outputParam & " """ & $cvtFileName & """""" 
	
	ConsoleWrite($cmd)
	Local $pID = Run($cmd, $workPath, @SW_HIDE, $STDERR_CHILD+$STDOUT_CHILD)
	While ProcessExists($pID)
		Sleep(500)
	WEnd
	;IceLogMsg("["&$g_totalFileCount&"]  转换完毕" & $inputFileTitle & $inputFileExt)
	Local $errMsg = StderrRead($pID)
	If ($errMsg <> "") Then
		$g_errCount += 1
		IceLogMsg(@CRLF&"文件转换出错: " & $inputFileName & @CRLF & $errMsg & @CRLF)
	EndIf
	if $g_bRelease==True Then 
;		FileDelete($tempTxtFileName)
	EndIf
EndFunc  

Func ConvertDir($strDir)
	Local $search = FileFindFirstFile($strDir & "\*.txt")
	Dim $FileListmine[1]
	Local $counttemp = 0
	While 1
		Local $filenameTemp = FileFindNextFile($search)
		If @error Then ExitLoop
		$counttemp += 1
		_ArrayAdd($FileListmine, $strDir & "\" & $filenameTemp)
	WEnd
	$FileListmine[0] = $counttemp
	;_ArrayDisplay($FileListmine)
	
	;$FileList = _FileListToArray ($strDir, "*.txt")
	GUICtrlSetData($ctlProgressInd, 0)
	For $c = 1 To $FileListmine[0]
		ConvertFile($FileListmine[$c])
		GUICtrlSetData($ctlProgressInd, $c * 100 / $FileListmine[0])
	Next
EndFunc

Func ConvertDirFileMultiLine($strMultiLine)
	Local $beginTimeStamp = TimerInit()	
	$g_totalFileCount = 0
	$g_errCount = 0
	Local $FileListArr = StringSplit($strMultiLine, @CRLF, 1)
	;_ArrayDisplay($FileListArr)
	;MsgBox(0, "", $strMultiLine)
	GUICtrlSetData($ctlEditOutput, "")
	GUICtrlSetData($ctlProgressTotal, 0)
	For $c = 1 To $FileListArr[0]
		GUICtrlSetData($ctlProgressTotal, $c * 100 / $FileListArr[0])
		If ($FileListArr[$c] == "") Then ContinueLoop
		Local $fileAttr = FileGetAttrib($FileListArr[$c])
		If @error Then
			MsgBox(4096, "Error", "Could not obtain attributes.")
			Return
		EndIf
		If StringInStr($fileAttr, "D") Then
			ConvertDir($FileListArr[$c])
		Else
			GUICtrlSetData($ctlProgressInd, 50)
			ConvertFile($FileListArr[$c])
			GUICtrlSetData($ctlProgressInd, 100)
		EndIf
	Next
	Local $costTime = TimerDiff($beginTimeStamp)
	If ($g_errCount <> 0) Then
		IceLogMsg("共耗时("&int($costTime/1000)&"秒) "&"转换" & $g_totalFileCount & "个文件完毕!共有" & $g_errCount & "个文件出错"&@CRLF)
	Else
		IceLogMsg("共耗时("&int($costTime/1000)&"秒) "&"转换" & $g_totalFileCount & "个文件完毕! 全部成功"&@CRLF)
	EndIf
EndFunc  

Func GetBookList()

	Local $strBody = _IEBodyReadText($g_oIE)


	Local $bookList = StringRegExp($strBody, "\[书评与下载\](.*?\r\n)", 3)
	;StringRegExp($strBody, "\[书发布与下载\].*"
	Local $bookListStr=""
	For $i=0 to UBound($bookList)-1
		$bookListStr = $bookListStr& $bookList[$i]
	Next

	return $bookListStr
EndFunc
