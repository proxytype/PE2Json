#include "Windows.h"
#include <iostream>
#include <stdio.h>
#include <string>
#pragma comment(lib, "Version.lib")

using namespace std;

const int MAX_FILEPATH_LENGTH = 255;
char filename[MAX_FILEPATH_LENGTH] = { 0 };

HANDLE hConsole = NULL;
WORD attributes = 0;

HANDLE file = NULL;
DWORD fileSize = NULL;
DWORD bytesRead = NULL;
bool is64bit = false;
string json;


void printTitle() {

	SetConsoleTextAttribute(hConsole,
		FOREGROUND_BLUE | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
	printf(" _______  _______  _______      ___  _______  _______  __    _ \n");
	printf("|       ||       ||       |    |   ||       ||       ||  |  | |\n");
	printf("|    _  ||    ___||____   |    |   ||  _____||   _   ||   |_| |\n");
	printf("|   |_| ||   |___  ____|  |    |   || |_____ |  | |  ||       |\n");
	printf("|    ___||    ___|| ______| ___|   ||_____  ||  |_|  ||  _    |\n");
	printf("|   |    |   |___ | |_____ |       | _____| ||       || | |   |\n");
	printf("|___|    |_______||_______||_______||_______||_______||_|  |__|\n");
	printf("---------------------------------------------------------------\n");
	printf(" by: RudeNetworks.com | version: 1.2 beta\n");

	SetConsoleTextAttribute(hConsole,
		FOREGROUND_GREEN);
}

void printUsage() {
	printf(" Usage:\n");
	printf(" pe2json.exe <PE file> <Json File>\n");
	printf(" pe2json.exe \"c:\windows\system32\kenel32.dll\" \"c:\k.dll\"\n");
	printf("---------------------------------------------------------------\n");
}

void replace(std::string& str, const std::string& from, const std::string& to) {
	if (from.empty())
		return;
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length();
	}
}

string convertOSversion(DWORD a, DWORD b, DWORD c) {
	char buffer[500];
	sprintf_s(buffer, "%d.%d (%d)", a, b, c);
	return string(buffer);
}

string convertVersion(DWORD a, DWORD b, DWORD c, DWORD d) {
	char buffer[500];
	sprintf_s(buffer, "%d.%d.%d.%d", a, b, c, d);
	return string(buffer);
}

string convertWord(WORD add) {
	char buffer[500];
	sprintf_s(buffer, "0x%x", add);
	return string(buffer);
}

string convertDword(PBYTE add) {
	char buffer[500];
	sprintf_s(buffer, "%s", add);
	return string(buffer);
}


void printNTHeader(PIMAGE_NT_HEADERS nTheader) {
	json.append(",\"nt\": {");

	json.append("\"signature\":\"");
	json.append(convertWord(nTheader->Signature));
	json.append("\"");

	json.append("}");

}


void printOSversion() {

	int osver = 0.0;

	NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);

	OSVERSIONINFOEXW osInfo;

	*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

	if (NULL != RtlGetVersion)
	{
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		RtlGetVersion(&osInfo);
		osver = osInfo.dwMajorVersion;
	}


	json.append(",\"os\": \"");
	json.append(convertOSversion(osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber));
	json.append("\"");

}

void printFileVersion(char* pszFilePath)
{
	DWORD               dwSize = 0;
	BYTE* pbVersionInfo = NULL;
	VS_FIXEDFILEINFO* pFileInfo = NULL;
	UINT                puLenFileInfo = 0;

	dwSize = GetFileVersionInfoSizeA(pszFilePath, NULL);
	if (dwSize == 0)
	{
		return;
	}

	pbVersionInfo = new BYTE[dwSize];

	if (!GetFileVersionInfoA(pszFilePath, 0, dwSize, pbVersionInfo))
	{
		return;
	}

	if (!VerQueryValue(pbVersionInfo, TEXT("\\"), (LPVOID*)&pFileInfo, &puLenFileInfo))
	{
		delete[] pbVersionInfo;
		return;
	}

	json.append(",\"versions\": {");
	json.append("\"file\": \"");


	json.append(convertVersion((pFileInfo->dwFileVersionLS >> 24) & 0xff,
		(pFileInfo->dwFileVersionLS >> 16) & 0xff,
		(pFileInfo->dwFileVersionLS >> 8) & 0xff,
		(pFileInfo->dwFileVersionLS >> 0) & 0xff));

	json.append("\",\"product\":\"");

	json.append(convertVersion(
		(pFileInfo->dwProductVersionLS >> 24) & 0xff,
		(pFileInfo->dwProductVersionLS >> 16) & 0xff,
		(pFileInfo->dwProductVersionLS >> 8) & 0xff,
		(pFileInfo->dwProductVersionLS >> 0) & 0xff));

	json.append("\"}");

}

void printSection(PIMAGE_SECTION_HEADER sectionHeader) {

	json.append("{");

	json.append("\"name\":\"");
	json.append((char*)sectionHeader->Name);
	json.append("\"");

	json.append(",\"virtualSize\":\"");
	json.append(convertWord(sectionHeader->Misc.VirtualSize));
	json.append("\"");

	json.append(",\"virtualAddress\":\"");
	json.append(convertWord(sectionHeader->VirtualAddress));
	json.append("\"");

	json.append(",\"sizeOfRawData\":\"");
	json.append(convertWord(sectionHeader->SizeOfRawData));
	json.append("\"");

	json.append(",\"pointerToRawData\":\"");
	json.append(convertWord(sectionHeader->PointerToRawData));
	json.append("\"");

	json.append(",\"pointerToRelocations\":\"");
	json.append(convertWord(sectionHeader->PointerToRelocations));
	json.append("\"");

	json.append(",\"pointerToLinenumbers\":\"");
	json.append(convertWord(sectionHeader->PointerToLinenumbers));
	json.append("\"");

	json.append(",\"numberOfRelocations\":\"");
	json.append(convertWord(sectionHeader->NumberOfRelocations));
	json.append("\"");

	json.append(",\"numberOfLinenumbers\":\"");
	json.append(convertWord(sectionHeader->NumberOfLinenumbers));
	json.append("\"");

	json.append(",\"characteristics\":\"");
	json.append(convertWord(sectionHeader->Characteristics));
	json.append("\"");

	json.append("}");

}

void printOptionalHeader(PIMAGE_OPTIONAL_HEADER  optionalHeader) {
	json.append(",\"optional\": {");

	json.append("\"magic\":\"");
	json.append(convertWord(optionalHeader->Magic));
	json.append("\"");

	json.append(",\"majorLinkerVersion\":\"");
	json.append(convertWord(optionalHeader->MajorLinkerVersion));
	json.append("\"");

	json.append(",\"minorLinkerVersion\":\"");
	json.append(convertWord(optionalHeader->MinorLinkerVersion));
	json.append("\"");

	json.append(",\"sizeOfCode\":\"");
	json.append(convertWord(optionalHeader->SizeOfCode));
	json.append("\"");

	json.append(",\"sizeOfInitializedData\":\"");
	json.append(convertWord(optionalHeader->SizeOfInitializedData));
	json.append("\"");

	json.append(",\"sizeOfUninitializedData\":\"");
	json.append(convertWord(optionalHeader->SizeOfUninitializedData));
	json.append("\"");

	json.append(",\"addressOfEntryPoint\":\"");
	json.append(convertWord(optionalHeader->AddressOfEntryPoint));
	json.append("\"");

	json.append(",\"baseOfCode\":\"");
	json.append(convertWord(optionalHeader->BaseOfCode));
	json.append("\"");

	json.append(",\"sectionAlignment\":\"");
	json.append(convertWord(optionalHeader->SectionAlignment));
	json.append("\"");

	json.append(",\"fileAlignment\":\"");
	json.append(convertWord(optionalHeader->FileAlignment));
	json.append("\"");

	json.append(",\"majorOperatingSystemVersion\":\"");
	json.append(convertWord(optionalHeader->MajorOperatingSystemVersion));
	json.append("\"");

	json.append(",\"minorOperatingSystemVersion\":\"");
	json.append(convertWord(optionalHeader->MinorOperatingSystemVersion));
	json.append("\"");

	json.append(",\"majorImageVersion\":\"");
	json.append(convertWord(optionalHeader->MajorImageVersion));
	json.append("\"");

	json.append(",\"minorImageVersion\":\"");
	json.append(convertWord(optionalHeader->MinorImageVersion));
	json.append("\"");

	json.append(",\"majorSubsystemVersion\":\"");
	json.append(convertWord(optionalHeader->MajorSubsystemVersion));
	json.append("\"");

	json.append(",\"minorSubsystemVersion\":\"");
	json.append(convertWord(optionalHeader->MinorSubsystemVersion));
	json.append("\"");

	json.append(",\"win32VersionValue\":\"");
	json.append(convertWord(optionalHeader->Win32VersionValue));
	json.append("\"");

	json.append(",\"sizeOfImage\":\"");
	json.append(convertWord(optionalHeader->SizeOfImage));
	json.append("\"");

	json.append(",\"sizeOfHeaders\":\"");
	json.append(convertWord(optionalHeader->SizeOfHeaders));
	json.append("\"");

	json.append(",\"checkSum\":\"");
	json.append(convertWord(optionalHeader->CheckSum));
	json.append("\"");

	json.append(",\"subsystem\":\"");
	json.append(convertWord(optionalHeader->Subsystem));
	json.append("\"");

	json.append(",\"dllCharacteristics\":\"");
	json.append(convertWord(optionalHeader->DllCharacteristics));
	json.append("\"");

	json.append(",\"sizeOfStackReserve\":\"");
	json.append(convertWord(optionalHeader->SizeOfStackReserve));
	json.append("\"");

	json.append(",\"sizeOfStackCommit\":\"");
	json.append(convertWord(optionalHeader->SizeOfStackCommit));
	json.append("\"");

	json.append(",\"sizeOfHeapReserve\":\"");
	json.append(convertWord(optionalHeader->SizeOfHeapReserve));
	json.append("\"");

	json.append(",\"loaderFlags\":\"");
	json.append(convertWord(optionalHeader->LoaderFlags));
	json.append("\"");

	json.append(",\"numberOfRvaAndSizes\":\"");
	json.append(convertWord(optionalHeader->NumberOfRvaAndSizes));
	json.append("\"");

	json.append("}");

}

void printDirectoryAddress(PIMAGE_DATA_DIRECTORY dataDirectory) {

	json.append(",\"directories\": {\"export\":{");

	json.append("\"address\":\"");
	json.append(convertWord(dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	json.append("\"");

	json.append(",\"size\":\"");
	json.append(convertWord(dataDirectory[0].Size));
	json.append("\"");

	json.append("}, \"import\":{");

	json.append("\"address\":\"");
	json.append(convertWord(dataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	json.append("\"");

	json.append(",\"size\":\"");
	json.append(convertWord(dataDirectory[1].Size));
	json.append("\"");

	json.append("}");
	json.append("}");
}

void printDosHeader(PIMAGE_DOS_HEADER dosHeader) {

	json.append(",\"dos\": {");

	json.append("\"e_magic\":\"");
	json.append(convertWord(dosHeader->e_magic));
	json.append("\"");

	json.append(",\"e_cblp\":\"");
	json.append(convertWord(dosHeader->e_cblp));
	json.append("\"");

	json.append(",\"e_cp\":\"");
	json.append(convertWord(dosHeader->e_cp));
	json.append("\"");

	json.append(",\"e_crlc\":\"");
	json.append(convertWord(dosHeader->e_crlc));
	json.append("\"");

	json.append(",\"e_cparhdr\":\"");
	json.append(convertWord(dosHeader->e_cparhdr));
	json.append("\"");

	json.append(",\"e_minalloc\":\"");
	json.append(convertWord(dosHeader->e_minalloc));
	json.append("\"");

	json.append(",\"e_maxalloc\":\"");
	json.append(convertWord(dosHeader->e_maxalloc));
	json.append("\"");

	json.append(",\"e_ss\":\"");
	json.append(convertWord(dosHeader->e_ss));
	json.append("\"");

	json.append(",\"e_sp\":\"");
	json.append(convertWord(dosHeader->e_sp));
	json.append("\"");

	json.append(",\"e_csum\":\"");
	json.append(convertWord(dosHeader->e_csum));
	json.append("\"");

	json.append(",\"e_ip\":\"");
	json.append(convertWord(dosHeader->e_ip));
	json.append("\"");

	json.append(",\"e_cs\":\"");
	json.append(convertWord(dosHeader->e_cs));
	json.append("\"");

	json.append(",\"e_lfarlc\":\"");
	json.append(convertWord(dosHeader->e_lfarlc));
	json.append("\"");

	json.append(",\"e_ovno\":\"");
	json.append(convertWord(dosHeader->e_ovno));
	json.append("\"");

	json.append(",\"e_oemid\":\"");
	json.append(convertWord(dosHeader->e_oemid));
	json.append("\"");

	json.append(",\"e_oeminfo\":\"");
	json.append(convertWord(dosHeader->e_oeminfo));
	json.append("\"");

	json.append(",\"e_lfanew\":\"");
	json.append(convertWord(dosHeader->e_lfanew));
	json.append("\"");

	json.append("}");

}

void printImportSection(PIMAGE_SECTION_HEADER importSection, PBYTE buffer, PIMAGE_DATA_DIRECTORY directory) {

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + importSection->PointerToRawData + (directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

	for (; importDescriptor->Name != 0; importDescriptor++) {

		char* dllName = (char*)(buffer + importSection->PointerToRawData + (importDescriptor->Name - importSection->VirtualAddress));

		json.append("{\"name\":\"");
		json.append(dllName);
		json.append("\",\"functions\": [");

		DWORD thunk = NULL;

		if (importDescriptor->OriginalFirstThunk == 0) {
			thunk = importDescriptor->FirstThunk;
		}
		else {
			thunk = importDescriptor->OriginalFirstThunk;
		}

		PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)(buffer + importSection->PointerToRawData + (thunk - importSection->VirtualAddress));

		for (; thunkData->u1.AddressOfData != 0; thunkData++) {

			json.append("\"");

			if (IMAGE_SNAP_BY_ORDINAL(thunkData->u1.AddressOfData)) {

				json.append(convertWord((WORD)thunkData->u1.AddressOfData));
			}
			else {
				json.append(convertDword((buffer + importSection->PointerToRawData + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2))));
			}

			json.append("\",");

		}

		json.pop_back();

		json.append("]},");
	}

	json.pop_back();

}

void saveFile(string output, char* fileOutput) {
	DWORD dwBytesWritten = 0;
	DWORD dwBytesToWrite = (DWORD)strlen(output.c_str());

	DeleteFileA(fileOutput);
	HANDLE     hFile = CreateFileA(fileOutput,                
		GENERIC_WRITE,          
		0,                      
		NULL,                  
		CREATE_NEW,             
		FILE_ATTRIBUTE_NORMAL,  
		NULL);                  

	WriteFile(
		hFile,           
		output.c_str(),      
		dwBytesToWrite,  
		&dwBytesWritten, 
		NULL);
}

void printExportSection(PIMAGE_EXPORT_DIRECTORY exported, DWORD exportDirVA) {

	unsigned long* names = (unsigned long*)((char*)exported + exported->AddressOfNames - exportDirVA);
	if (exported->NumberOfNames != 0) {
		json.append(",\"exports\":[");
		for (unsigned long j = 0; j < exported->NumberOfNames; j++)
		{
			char* name = (char*)exported + names[j] - exportDirVA;
			json.append("\"");
			json.append(name);
			json.append("\",");

		}

		json.pop_back();
		json.append("]");
	}


}

int main(int argc, char* argv[])
{
	CONSOLE_SCREEN_BUFFER_INFO Info;
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleScreenBufferInfo(hConsole, &Info);
	attributes = Info.wAttributes;

	printTitle();

	if (argc < 3) {
		printUsage();
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attributes);
		return -1;
	}

	memcpy_s(&filename, MAX_FILEPATH_LENGTH, argv[1], MAX_FILEPATH_LENGTH);
	file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE) {
		printf(" Could not read file\n");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attributes);
		return -1;
	}

	json.append("{\"filename\":\"");

	printf(" Input: %s\n", argv[1]);
	string filename(argv[1]);

	string output(argv[2]);
	printf(" Output: %s\n", argv[2]);

	replace(filename, "\\", "\\\\");

	json.append(filename);

	json.append("\",\"size\":");

	fileSize = GetFileSize(file, NULL);

	json.append(std::to_string(fileSize));
	printOSversion();
	json.append(",\"is64\":");


	PBYTE buffer = PBYTE(LocalAlloc(LPTR, fileSize));

	BOOL success = ReadFile(file, buffer, fileSize, &bytesRead, NULL);

	if (success) {
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
		printf(" Reading Headers: DOS, NT, FILE, OPTIONAL\n");
		if (dosHeader != NULL && dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {

			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
			PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)&ntHeader->FileHeader;

			if (fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
				is64bit = true;
				json.append("1");


			}
			else {
				is64bit = false;
				json.append("0");
			}

			PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
			DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

			PIMAGE_OPTIONAL_HEADER  optionalHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeader->OptionalHeader;

			PIMAGE_DATA_DIRECTORY directory = (PIMAGE_DATA_DIRECTORY)&ntHeader->OptionalHeader.DataDirectory;
			DWORD importDirectoryRVA = directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

			DWORD exportDirectoryRVA = directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			DWORD exportDirSize = directory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

			PIMAGE_SECTION_HEADER importSection = NULL;
			PIMAGE_EXPORT_DIRECTORY exports = NULL;

			printf(" Finding Imports and Exports...\n");
			for (int i = 0; i < fileHeader->NumberOfSections; i++)
			{
				int indexOffset = i * sectionSize;
				sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + indexOffset);
				if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
					importSection = sectionHeader;

				}

				if (sectionHeader->VirtualAddress <= exportDirectoryRVA
					&& sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize >= exportDirectoryRVA + exportDirSize)
				{
					exports = PIMAGE_EXPORT_DIRECTORY(buffer + sectionHeader->PointerToRawData + exportDirectoryRVA - sectionHeader->VirtualAddress);
				}
			}

			printFileVersion(argv[1]);
			printDosHeader(dosHeader);
			printNTHeader(ntHeader);
			printDirectoryAddress(directory);
			printOptionalHeader(optionalHeader);

			json.append(",\"sections\":[");
			printf(" Analyze Sections...\n");
			for (int i = 0; i < fileHeader->NumberOfSections; i++)
			{
				int indexOffset = i * sectionSize;
				sectionHeader = (PIMAGE_SECTION_HEADER)(buffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + indexOffset);
				printSection(sectionHeader);

				if (i != fileHeader->NumberOfSections - 1) {
					json.append(",");
				}

			}

			json.append("]");

			if (importSection != NULL) {
				printf(" Analyze Imports...\n");
				json.append(",\"imports\":[");
				printImportSection(importSection, buffer, directory);
				json.append("]");
			}

			if (exports != NULL) {
				printf(" Analyze Exports...\n");
				printExportSection(exports, exportDirectoryRVA);
			}

			json.append("}");

		}
		printf(" Write Json...\n");
		saveFile(json, argv[2]);
	}


	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attributes);
	return 0;
}

