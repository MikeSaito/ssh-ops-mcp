// One ASCII JSON frame avoids EOF waits and console code-page corruption.
export function powershellInput(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')) + '\n';
}

// Load only Windows PowerShell's own modules, independent of client module paths/cache.
export const powershellPrelude = "$ErrorActionPreference='Stop'; $PSModuleAutoLoadingPreference='None'; " +
  "Import-Module ([IO.Path]::Combine($PSHOME,'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop; " +
  "Import-Module ([IO.Path]::Combine($PSHOME,'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1')) -ErrorAction Stop; ";

export function powershellEnvironment(system = process.env) {
  const env = Object.fromEntries(Object.entries(system).filter(([key]) => !['PSMODULEPATH', 'WINPSMODULEPATH', 'PSMODULEANALYSISCACHEPATH'].includes(key.toUpperCase())));
  env.PSModuleAnalysisCachePath = 'NUL';
  return env;
}
