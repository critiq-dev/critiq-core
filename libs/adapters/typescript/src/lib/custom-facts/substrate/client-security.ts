import { isAuthLikeText, isAuthStorageKey } from '../../auth-vocabulary';

export interface ElectronDangerousWebPreference {
  name: string;
  insecureBooleanValue: boolean;
}

export const electronDangerousWebPreferences: readonly ElectronDangerousWebPreference[] =
  [
    {
      name: 'allowRunningInsecureContent',
      insecureBooleanValue: true,
    },
    {
      name: 'contextIsolation',
      insecureBooleanValue: false,
    },
    {
      name: 'enableRemoteModule',
      insecureBooleanValue: true,
    },
    {
      name: 'nodeIntegration',
      insecureBooleanValue: true,
    },
    {
      name: 'sandbox',
      insecureBooleanValue: false,
    },
    {
      name: 'webSecurity',
      insecureBooleanValue: false,
    },
  ] as const;

const electronTrustedOriginValidatorNames = new Set([
  'allowlistedOrigin',
  'assertAllowedOrigin',
  'assertTrustedSenderFrame',
  'assertTrustedWebContents',
  'ensureAllowedOrigin',
  'ensureTrustedSender',
  'validateAllowedOrigin',
  'validateTrustedOrigin',
  'validateTrustedSender',
]);

const electronPrivilegedIpcSinkPattern =
  /\b(?:BrowserWindow|dialog\.(?:showOpenDialog|showSaveDialog)|exec|fs\.(?:appendFile|appendFileSync|readFile|readFileSync|rm|rmSync|unlink|unlinkSync|writeFile|writeFileSync)|openExternal|process\.env|shell\.(?:openExternal|openPath|showItemInFolder)|spawn|systemPreferences|webContents)\b/u;

export function isElectronTrustedOriginValidatorName(
  calleeText: string | undefined,
): boolean {
  return Boolean(
    calleeText && electronTrustedOriginValidatorNames.has(calleeText),
  );
}

export function isElectronSensitiveStorageKey(
  text: string | undefined,
): boolean {
  return isAuthStorageKey(text) || isAuthLikeText(text);
}

export function isLikelyPrivilegedElectronIpcBody(
  bodyText: string | undefined,
): boolean {
  return Boolean(
    bodyText && electronPrivilegedIpcSinkPattern.test(bodyText),
  );
}
