@{
    GUID = '987bd909-5906-4e3c-b40d-c03660f97ab3'
    Author = 'Mike Garvey'
	Description = "Creates a WinRM SSL listener on the local machine on port 5986."
    CompanyName = 'Yevrag35, LLC.'
    Copyright = '© 2018 Yevrag35, LLC.  All rights reserved.'
    ModuleVersion = '0.1.0'
    PowerShellVersion = '4.0'
	DotNetFrameworkVersion = '4.5'
    NestedModules = @('CreateWinRmSslListener.psm1')
    RequiredAssemblies = @('Security.Cryptography.dll')
    FunctionsToExport = @('Create-WinRmSslListener')
	CmdletsToExport = ''
	VariablesToExport = ''
	AliasesToExport = '*'
	FileList = @(
        'CreateWinRmSslListener.psd1',
        'CreateWinRmSslListener.psm1',
        'Security.Cryptography.dll'
	)
}