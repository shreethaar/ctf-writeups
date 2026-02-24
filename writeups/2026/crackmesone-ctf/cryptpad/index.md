# CryptPad

### 1. Renamed `sub_4013A2` to `unpaid_version_decrypt_func` and `sub_401718` to `enc_function`, reanalyze WNDPROC callback function

```c
int __stdcall sub_4011A0(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  int result; // eax
  int v5; // [esp-4h] [ebp-10h]
  int v6; // [esp+0h] [ebp-Ch]
  int v7; // [esp+4h] [ebp-8h]

  if ( Msg == 2 )
    goto LABEL_21;
  if ( Msg == 273 )
  {
    switch ( (unsigned __int16)wParam )
    {
      case 'e':
        SendMessageA(dword_4024D1, 0xCu, (WPARAM)Caption, 0);
        nullsub_1();
        SetWindowTextA((HWND)hInstance, Caption);
        String[0] = 0;
        return 0;
      case 'p':
        return MessageBoxA(a1, aCryptpad10IsAn, Caption, 0);
      case 'o':
        return MessageBoxA(a1, aToRegisterSend, Caption, 0);
      case 'f':
        return unpaid_version_decrypt_func(v6, v7);
      case 'g':
        result = file_input_handle_function(a1);
        if ( result )
        {
          SetWindowTextA(a1, String);
          sub_4013BD();
          return 0;
        }
        return result;
    }
    if ( (unsigned __int16)wParam != 105 )
      return DefWindowProcA(hWnd, Msg, wParam, lParam);
```

Switch case table indicating if the `wParam` is `g`, it will proceed to the `file_input_handle_function` and store the result.  

### 2. `struct_4024D` is `OPENFILENAMEA` struct

```c
  stru_40242D.lStructSize = 76;
  stru_40242D.hwndOwner = a1;
  stru_40242D.lpstrFilter = aEncryptedFiles;
  stru_40242D.lpstrFile = String;
  stru_40242D.nMaxFile = 260;
  stru_40242D.Flags = 526342;
  stru_40242D.lpstrDefExt = aTxt;
```

From `file_input_handle_function`, it uses `OPENFILENAME` struct and pass it as a pointer `GetSaveFileName` function

### 3. At address `0x004013BD` contain function that encrypts the file

```c
 ProcessHeap = GetProcessHeap();
  if ( ProcessHeap
    && (hHeap = ProcessHeap,
        NumberOfBytesWritten = GetWindowTextLengthA(dword_4024D1) + 1,
        RandomBufferLength = 64 - NumberOfBytesWritten % 0x40,
        (v1 = (CHAR *)HeapAlloc(hHeap, 0, NumberOfBytesWritten + RandomBufferLength)) != 0)
    && (lpMem = v1, (FileA = CreateFileA(String, 0x40000000u, 0, 0, 2u, 0x80u, 0)) != 0) )
  {
    hObject = FileA;
    GetWindowTextA(dword_4024D1, lpMem, NumberOfBytesWritten);
    sub_40166B(&lpMem[NumberOfBytesWritten], RandomBufferLength);
    sub_40166B(&byte_4024C5, 8u);
    v3 = sub_4014EB(lpMem, NumberOfBytesWritten, 1);
    WriteFile(hObject, lpMem, v3, &NumberOfBytesWritten, 0);
    CloseHandle(hObject);
  }
```

From function `sub_40166B`, it uses a blob byte at address `0x004024C5` which is `.data:004024C5 byte_4024C5     db 0DEh, 0BCh, 0Ah, 89h, 67h, 45h, 23h, 1`
and used in function `sub_4014EB`

### 4. Understand the encryption algorithm of `sub_4014EB`

```c
char __stdcall sub_4014EB(_BYTE *a1, int a2, int a3)
{
  unsigned int v3; // ecx
  _BYTE *v4; // esi
  int v5; // eax
  char result; // al
  _BYTE *v7; // esi
  _BYTE *v8; // edi
  DWORD v9; // ecx
  int v10; // edx
  int v11; // ecx
  _BYTE *v12; // esi
  int v13; // ecx
  int v14; // ebx
  int v15; // ebx
  _BYTE *v16; // esi
  int v17; // eax
  int v18; // ecx
  char v19; // dl
  _BYTE *v20; // edx
  int v21; // eax
  int v22; // ebx
  int v23; // ecx
  int v24; // ecx
  char v25; // dh
  char v26; // dl
  _BYTE *v27; // esi
  _BYTE *v28; // edi
  DWORD v29; // ecx
  int v30; // edx
  _BYTE *v31; // edi
  _BYTE *v32; // [esp-8h] [ebp-Ch]
  int v33; // [esp-4h] [ebp-8h]

  if ( a3 )
  {
    if ( a3 != 1 )
      return MessageBoxA(0, 0, 0, 0);
  }
  else
  {
    v3 = *(_DWORD *)&a1[a2 - 1];
    v4 = &a1[a2 - 1 - v3];
    qmemcpy(byte_4024C5, v4, v3);
    v5 = *((_DWORD *)v4 - 1);
    *((_DWORD *)v4 - 1) = 0;
    a2 = v5;
  }
  v7 = a1;
  v8 = byte_4024C5;
  v9 = NumberOfBytesWritten;
LABEL_6:
  v10 = 0;
  do
  {
    *v7++ ^= *v8++;
    if ( ++v10 == 8 )
      goto LABEL_6;
    --v9;
  }
  while ( v9 );
  v11 = 256;
  do
  {
    byte_403795[(unsigned __int8)-(char)v11] = -(char)v11;
    --v11;
  }
  while ( v11 );
  v12 = &unk_403695;
  v13 = 256;
  v14 = 0;
  do
  {
    if ( v14 >= 8 )
      v14 = 0;
    *v12++ = byte_4024C5[v14++];
    --v13;
  }
  while ( v13 );
  v15 = 0;
  v16 = v12 - 256;
  v17 = 0;
  v18 = 256;
  do
  {
    LOBYTE(v15) = byte_403795[v17] + v16[v17] + v15;
    v19 = byte_403795[v17];
    byte_403795[v17] = byte_403795[v15];
    byte_403795[v15] = v19;
    ++v17;
    --v18;
  }
  while ( v18 );
  v20 = a1;
  v21 = 0;
  v22 = 0;
  v23 = a2;
  do
  {
    v33 = v23;
    v24 = (unsigned __int8)(v21 + 1);
    v32 = v20;

