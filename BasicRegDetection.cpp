/*
                                         Basic Registery based detection unit:
        Created for Epsilon Anti-Virus v.1.0, all this does is to remove non-persistent and non-rootkit Malwares
        from the system, works very well. Do keep in mind changing locations of registeries and other location's
        can result in false-postive results thus destroying vital pieces of Software from system. 
        
        Created by SpaceWorm, Cplusplus Forum. 
        Feel free to PM me regarding queries and help related to this or programming.
        Profile Link: http://www.cplusplus.com/user/SpaceWorm/
        
        Thanks!
*/

#include <Windows.h>
#include <Aclapi.h>

/* SetFilePrivileges() 
   if successful - return TRUE  if unsuccessful - return FALSE
*/
bool SetFilePrivileges(wchar_t* w_FilePath, DWORD dwSetFilePermissions,bool bKillOrNot) {
        if ( w_FilePath == 0 || lstrlenW(w_FilePath) < 1 )
                return false;
 
        PACL              m_paDACL   = 0;
        EXPLICIT_ACCESS_A m_stDeny   = { 0 };
        EXPLICIT_ACCESS_A m_stAllow  = { 0 };
        DWORD             m_dwError  = 0;
 
     
        BuildExplicitAccessWithNameA(&m_stDeny, "CURRENT_USER", dwSetFilePermissions, (bKillOrNot)?DENY_ACCESS:GRANT_ACCESS, NO_INHERITANCE);

        if ( (m_dwError = SetEntriesInAclA(1, &m_stDeny, 0, &m_paDACL)) != ERROR_SUCCESS )
                return false;

        if ( (m_dwError = SetNamedSecurityInfoW(w_FilePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, m_paDACL, NULL)) != ERROR_SUCCESS ) {
                LocalFree(m_paDACL);
 
                return false;
        }
 
        return true;
}
 
int BasicRegCheckUp()
{
        wchar_t w_mzMalware[260];
        wchar_t m_wszUsers[260];
        wchar_t m_wszAllUsers[260];
        wchar_t m_wszValueName[256];
        DWORD   Type            = REG_SZ;
        DWORD   mSize            = _countof(w_mzMalware);
        DWORD   m_dwNameLength      = _countof(m_wszValueName);
        DWORD   m_NumWrote        = 0;
        HKEY    m_hKey              = 0;
        HANDLE  m_hFile             = 0;
        UINT    i                   = 0;
 
        memset(w_mzMalware, 0, sizeof(w_mzMalware));
        memset(m_wszValueName, 0, sizeof(m_wszValueName));
        memset(m_wszUsers, 0, sizeof(m_wszUsers));
        memset(m_wszAllUsers, 0, sizeof(m_wszAllUsers));
 
        if ( ExpandEnvironmentStringsW(L"%USERPROFILE%", m_wszUsers, _countof(m_wszUsers) - 1) == NULL )
                _asm mov eax , 0
        else
                CharLowerBuffW(m_wszUsers, _countof(m_wszUsers));
 
        if ( ExpandEnvironmentStringsW(L"%ALLUSERSPROFILE%", m_wszAllUsers, _countof(m_wszAllUsers) - 1) == 0 )
                _asm mov eax , 0
        else
                CharLowerBuffW(m_wszAllUsers, _countof(m_wszAllUsers));
 
        if ( RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0, KEY_QUERY_VALUE, &m_hKey) == ERROR_SUCCESS ) {
             
                while ( RegEnumValueW(m_hKey, i++, m_wszValueName, &m_dwNameLength, 0 , &Type, (LPBYTE)w_mzMalware, &mSize) == ERROR_SUCCESS ) {
                        CharLowerBuffW(w_mzMalware, (mSize / 2));
 
                        if ( lstrlenW(w_mzMalware) != 0 && (wcsstr(w_mzMalware, m_wszUsers) != 0 || wcsstr(w_mzMalware, m_wszAllUsers) != 0) &&
                                 GetFileAttributesW(w_mzMalware) != INVALID_FILE_ATTRIBUTES ) {
                                
                                SetFilePrivileges(w_mzMalware, 0x00040021|FILE_WRITE_ATTRIBUTES, true);
                        } 
                        m_dwNameLength = _countof(m_wszValueName);
                        mSize = _countof(w_mzMalware);
                }
        }
 
return 0;
}
